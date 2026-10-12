"""Linux-runner browser check; no endpoint agent or response action is started."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
root = args.root.resolve()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
python = root / ".venv/bin/python"
env = os.environ.copy()
env.update(QWR_ENVIRONMENT="development", QWR_API_HOST="127.0.0.1", QWR_API_PORT="8002",
           QWR_DATABASE_URL=f"sqlite:///{(out/'browser.db').as_posix()}",
           QWR_ENROLLMENT_TOKEN="synthetic-browser-qualification-enrollment",
           QWR_SEED_DEMO="false", NEXT_TELEMETRY_DISABLED="1")
subprocess.run([str(python), "-m", "alembic", "upgrade", "head"], cwd=root/"backend", env=env, check=True)
processes=[]
handles=[]
def start(command, cwd, name):
    stream=(out/name).open("w",encoding="utf-8"); handles.append(stream)
    process=subprocess.Popen(command,cwd=cwd,env=env,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
    processes.append(process)
    return process

def ready(url, process):
    deadline=time.monotonic()+90
    while time.monotonic()<deadline:
        if process.poll() is not None: raise RuntimeError(f"Service exited: {url}")
        try:
            with urllib.request.urlopen(url,timeout=2) as response:
                if response.status==200:return
        except OSError:pass
        time.sleep(.25)
    raise RuntimeError(f"Service readiness failed: {url}")

try:
    backend=start([str(python),"-m","uvicorn","app.main:runtime_app","--factory","--host","127.0.0.1","--port","8002"],root/"backend","backend.log")
    ready("http://127.0.0.1:8002/health",backend)
    subprocess.run([str(python),str(root/"scripts/seed_demo.py"),"--api-url","http://127.0.0.1:8002"],cwd=root,env=env,check=True)
    frontend=start(["node",str(root/"frontend/node_modules/next/dist/bin/next"),"start","-H","127.0.0.1","-p","3001"],root/"frontend","frontend.log")
    ready("http://127.0.0.1:3001/",frontend)
    errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        page=browser.new_page(viewport={"width":1450,"height":1050})
        page.on("pageerror",lambda error:errors.append(str(error)))
        try:
            for name,path in [("overview","/"),("incidents","/incidents"),("hosts","/hosts"),("agents","/agents"),("events","/events")]:
                page.goto("http://127.0.0.1:3001"+path,wait_until="networkidle")
                expect(page.locator("h1")).to_be_visible()
                expect(page.get_by_text("API request failed",exact=False)).to_have_count(0)
                expect(page.get_by_role("navigation").get_by_role("link",name="Incidents",exact=True)).to_be_visible()
                assert page.locator("header").evaluate("e=>getComputedStyle(e).position")=="sticky"
                title=page.locator("h1").evaluate("e=>({size:parseFloat(getComputedStyle(e).fontSize),weight:getComputedStyle(e).fontWeight})")
                assert title["size"]>=28 and int(title["weight"])>=600,title
                page.screenshot(path=str(out/f"{name}.png"),full_page=True)
            page.goto("http://127.0.0.1:3001/incidents",wait_until="networkidle")
            expect(page.locator("tbody tr").first).to_be_visible()
            page.locator('tbody a[href^="/incidents/"]').first.click()
            page.wait_for_load_state("networkidle")
            expect(page.locator("h1")).to_be_visible()
            expect(page.get_by_text("API request failed",exact=False)).to_have_count(0)
            page.screenshot(path=str(out/"incident-detail.png"),full_page=True)
            assert not errors,errors
        except Exception:
            import traceback
            (out/"failure.txt").write_text(traceback.format_exc(),encoding="utf-8")
            page.screenshot(path=str(out/"failure.png"),full_page=True)
            (out/"failure.html").write_text(page.content(),encoding="utf-8")
            raise
        finally:browser.close()
    receipt={"decision":"PASS","browser":"Chromium","routes":6,"synthetic_data_only":True,
             "endpoint_agents_started":0,"response_actions_requested":0,"javascript_errors":errors,
             "source_sha":subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip(),
             "lock_sha256":hashlib.sha256((root/"frontend/package-lock.json").read_bytes()).hexdigest()}
    (out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")
finally:
    for process in reversed(processes):
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
    for stream in handles:stream.close()
