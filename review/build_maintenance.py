"""Build only the reviewed maintenance delta; never merge the vNext tree."""
from pathlib import Path
import ast
import hashlib
import shutil
import subprocess
import sys

r=Path(sys.argv[1]).resolve(); f=Path(sys.argv[2]).resolve()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()=='5cf817422091a6e594e6b4e69b2c357a404ba1fe'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=f,text=True).strip()=='972bac1be241f2701d362b6a2e471423f66f8517'
# Copy only the two private-file writer functions, not their feature executors.
for name,func in [('response_agent.py','_atomic_json'),('enroll_response_agent.py','_private_json')]:
    source=(f/'scripts'/name).read_text();p=r/'scripts'/name;target=p.read_text()
    sn=next(x for x in ast.parse(source).body if isinstance(x,ast.FunctionDef) and x.name==func)
    tn=next(x for x in ast.parse(target).body if isinstance(x,ast.FunctionDef) and x.name==func)
    lines=target.splitlines(True);lines[tn.lineno-1:tn.end_lineno]=source.splitlines(True)[sn.lineno-1:sn.end_lineno]
    target=''.join(lines)
    if 'import tempfile\n' not in target:target=target.replace('import time\n','import time\nimport tempfile\n')
    p.write_text(target)
p=r/'scripts/enroll_response_agent.py';s=p.read_text().replace('import stat\n','')
s=s.replace('config_path = (args.config or state_dir / "agent-config.json").expanduser().resolve()', '''# Preserve the final pathname so a symlink cannot be resolved away before
    # the private writer checks it. Refuse before creating a remote enrollment.
    config_path = (args.config or state_dir / "agent-config.json").expanduser().absolute()
    if config_path.is_symlink():
        print("agent config must not be a symlink")
        return 2
    if config_path.exists() and not args.force:
        print("agent config already exists; use --force only for an intentional replacement")
        return 2''')
p.write_text(s)
files=['frontend/.gitignore','frontend/package-lock.json','frontend/package.json','frontend/postcss.config.mjs','frontend/src/app/globals.css','scripts/verify_frontend_browser.py','docs/FRONTEND_SECURITY_UPDATE.md','backend/tests/test_private_state_writes.py']
for name in files:
    p=r/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f/name,p)
(r/'frontend/next-env.d.ts').unlink(missing_ok=True)
for p in (r/'frontend/src').rglob('*.tsx'):
    s=p.read_text()
    if 'outline-none' in s:p.write_text(s.replace('outline-none','outline-hidden'))
p=r/'backend/tests/test_private_state_writes.py'
p.write_text(p.read_text()+'''

@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink regression")
def test_enrollment_cli_refuses_symlink_before_network(tmp_path, monkeypatch):
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"PRESERVE")
    alias = tmp_path / "alias.json"
    alias.symlink_to(existing)
    monkeypatch.setenv("QWR_ENROLLMENT_TOKEN", "synthetic-enrollment-test-token")
    monkeypatch.setattr(sys, "argv", ["enroll_response_agent.py", "--host-id", "synthetic-host", "--config", str(alias), "--force"])
    with patch.object(enrollment, "urlopen", side_effect=AssertionError("network must not run")):
        assert enrollment.main() == 2
    assert alias.is_symlink() and existing.read_bytes() == b"PRESERVE"


def test_enrollment_cli_existing_config_refused_before_network(tmp_path, monkeypatch):
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"PRESERVE")
    monkeypatch.setenv("QWR_ENROLLMENT_TOKEN", "synthetic-enrollment-test-token")
    monkeypatch.setattr(sys, "argv", ["enroll_response_agent.py", "--host-id", "synthetic-host", "--config", str(existing)])
    with patch.object(enrollment, "urlopen", side_effect=AssertionError("network must not run")):
        assert enrollment.main() == 2
    assert existing.read_bytes() == b"PRESERVE"
''')
(r/'backend/tests/test_maintenance_boundary.py').write_text('''"""Maintenance must not promote the unrelated process-control feature branch."""
from app.services.action_registry import ACTION_REGISTRY


def test_maintenance_retains_parameterless_approval_gated_actions():
    assert set(ACTION_REGISTRY) == {
        'restart_quietward_demo_service', 'collect_host_diagnostic',
        'collect_process_diagnostic', 'collect_network_diagnostic',
    }
    for definition in ACTION_REGISTRY.values():
        assert definition.approval_required is True
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({'pid': 999999})
        assert definition.validate_parameters({'command': 'not-executed'})
''')
expected={
'scripts/response_agent.py':'2bca4229ea0d8901aa5afa5c5171f7cc3bd56b94a8a68116a098ea3e9b5c505a',
'scripts/enroll_response_agent.py':'799a5380216d54668a579ac16265e925856491bddacc075a67f204b98a6f8f3e',
'frontend/package-lock.json':'66dcf84c2a412fe80e1775093259de589fbc15f030b286e852be471f59c75ff0',
'frontend/package.json':'ff921df9d3c2c1b4edf30ab702ba8d2f23b0d3b43a2e77fe760ed56fcb856f03',
'frontend/postcss.config.mjs':'65572d5fde836180cba54e1ac6ff1ec309ef6aa925662e9cd04b32b53c5bee35',
'frontend/src/app/globals.css':'c4106b71ce984e948de9052721b15a922b3853792fb4a6b3be60afaf7677ac86',
'frontend/src/app/incidents/[id]/page.tsx':'b648b2d05c21e1600a48212407d11d2691a859a5072da8e380b8b2447026a2d7',
'frontend/src/components/ResponseActions.tsx':'6c5af968d0f40a2beb7b11cceaa1178b2e0cddc1aa58a9b1d246e095aa558d32'}
for name,digest in expected.items():
    assert hashlib.sha256((r/name).read_bytes()).hexdigest()==digest,name
# The authority-owning sources must still match main byte-for-byte.
protected=['backend/app/services/action_registry.py','backend/app/services/policy_service.py','protocol/quietward-action-schema-v1.json','backend/app/analyst_auth.py']
for name in protected:
    assert (r/name).read_bytes()==subprocess.check_output(['git','show','HEAD:'+name],cwd=r),name
assert not (r/'scripts/process_containment.py').exists()
assert not (r/'scripts/evidence_store.py').exists()
print('Maintenance production hashes and unchanged authority boundary: PASS')
