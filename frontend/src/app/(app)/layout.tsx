'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import StatusIndicator from '@/components/StatusIndicator';
import NotificationCenter from '@/components/NotificationCenter';

const navLinks = [
  { href: '/dashboard', label: 'Dashboard',     icon: '📊', color: 'group-hover:text-brand-primary' },
  { href: '/viewer',    label: 'Secure Viewer', icon: '👁️', color: 'group-hover:text-brand-accent'  },
  { href: '/admin',     label: 'Admin Console', icon: '🛡️', color: 'group-hover:text-brand-primary' },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();

  const handleSignOut = async () => {
    const storedInvoice = localStorage.getItem('invoice_id');
    if (storedInvoice) {
      const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';
      await fetch(`${API}/signout?invoice_id=${storedInvoice}`, {
        method: 'POST',
      }).catch(() => {});
    }
    localStorage.removeItem('auth_token');
    localStorage.removeItem('invoice_id');
    document.cookie = 'auth_token=; Max-Age=0; path=/; SameSite=Strict';
    window.location.href = '/auth/signin';
  };

  return (
    <div className="bg-brand-bg text-text-main flex min-h-screen overflow-hidden">

      {/* SIDEBAR */}
      <aside className="w-64 bg-brand-surface border-r border-slate-800 flex flex-col shrink-0">
        <div className="p-6 border-b border-slate-800">
          <h1 className="text-xl font-bold tracking-tighter">
            SECURE<span className="text-brand-primary">SHIELD</span>
          </h1>
          <p className="text-[10px] text-brand-accent font-mono mt-1 uppercase">DRM Control Enclave</p>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navLinks.map(({ href, label, icon, color }) => (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 p-3 rounded-lg transition-colors group ${
                pathname === href
                  ? 'bg-slate-700/60 text-white'
                  : 'hover:bg-slate-700/50 text-text-muted'
              }`}
            >
              <span className={color}>{icon}</span>
              <span className="text-sm font-medium">{label}</span>
              {pathname === href && (
                <span className="ml-auto w-1.5 h-1.5 rounded-full bg-brand-primary" />
              )}
            </Link>
          ))}
        </nav>

        {/* SERVICE MONITORING BOX */}
        <div className="p-4 bg-black/20 m-4 rounded-xl border border-slate-800">
          <h3 className="text-[10px] font-bold text-slate-500 uppercase mb-2 px-2">Infrastructure</h3>
          <StatusIndicator service="API" />
          <StatusIndicator service="PostgreSQL" />
        </div>

        {/* SIGN OUT */}
        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleSignOut}
            className="w-full flex items-center gap-3 p-3 text-brand-error hover:bg-red-500/10 rounded-lg transition-colors"
          >
            <span>🚪</span>
            <span className="text-sm font-bold uppercase tracking-tight">Sign Out</span>
          </button>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col overflow-hidden bg-secure-gradient">
        <header className="h-16 border-b border-slate-800 bg-brand-bg/50 backdrop-blur-md flex items-center justify-between px-8 shrink-0 sticky top-0 z-40">
          <div className="flex items-center gap-4">
            {/* Здесь можно добавить хлебные крошки или поиск */}
          </div>

          <div className="flex items-center gap-6">
            <NotificationCenter />

            <div className="h-8 w-px bg-slate-800" />

            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-xs font-bold">Admin_Core</p>
                <p className="text-[10px] text-brand-success font-mono">Root Access</p>
              </div>
              <div className="w-10 h-10 rounded-full border-2 border-brand-primary p-0.5">
                <div className="w-full h-full rounded-full bg-slate-700 flex items-center justify-center text-xs font-bold">
                  AD
                </div>
              </div>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-8">
          {children}
        </main>
      </div>

    </div>
  );
}
