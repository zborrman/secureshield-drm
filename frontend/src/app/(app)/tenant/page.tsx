"use client";

import { useState } from "react";
import TenantSelector from "../../../components/TenantSelector";
import TenantDashboard from "../../../components/TenantDashboard";

interface TenantAuth {
  slug: string;
  adminKey: string;
}

export default function TenantPage() {
  const [auth, setAuth] = useState<TenantAuth | null>(null);

  if (!auth) {
    return <TenantSelector onLogin={setAuth} />;
  }

  return <TenantDashboard auth={auth} onLogout={() => setAuth(null)} />;
}
