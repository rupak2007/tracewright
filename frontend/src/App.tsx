import { useId, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";

import { getToken, setToken } from "./api/client";
import { IncidentPage } from "./pages/IncidentPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { OverviewPage } from "./pages/OverviewPage";

function TokenField() {
  const id = useId();
  const [value, setValue] = useState(getToken());
  return (
    <div className="token">
      <label htmlFor={id}>API token (only if the server requires one)</label>
      <input
        id={id}
        type="password"
        autoComplete="off"
        value={value}
        onChange={(e) => {
          setValue(e.target.value);
          setToken(e.target.value);
        }}
      />
    </div>
  );
}

export function App() {
  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="top">
        <nav aria-label="Main">
          <Link to="/" className="brand">
            Tracewright
          </Link>
          <span className="muted"> offline network incident investigation</span>
        </nav>
        <TokenField />
      </header>
      <main id="main">
        <Routes>
          <Route path="/" element={<InvestigationsPage />} />
          <Route path="/investigations/:id" element={<OverviewPage />} />
          <Route path="/incidents/:id" element={<IncidentPage />} />
          <Route path="*" element={<p>Page not found. <Link to="/">Back to investigations</Link></p>} />
        </Routes>
      </main>
      <footer>
        <p className="muted">
          Findings are rule and statistics observations; the analyst decides what they mean.
        </p>
      </footer>
    </>
  );
}
