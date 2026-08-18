import Link from "next/link";

export default function NotFound() { return <div className="not-found"><span>404</span><h1>Investigation not found</h1><p>The incident may have been removed or the identifier is invalid.</p><Link href="/incidents">Return to incidents</Link></div>; }
