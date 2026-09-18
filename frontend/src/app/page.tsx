"use client";

import React, { useState } from "react";
import { Navbar, NavTab } from "../components/Navbar";
import { ScannerTab } from "../components/ScannerTab";
import { RedTeamTab } from "../components/RedTeamTab";
import { AuditTab } from "../components/AuditTab";
import { StatsTab } from "../components/StatsTab";
import { DeveloperTab } from "../components/DeveloperTab";

export default function Home() {
  const [activeTab, setActiveTab] = useState<NavTab>("scanner");

  return (
    <div className="app-container">
      <Navbar activeTab={activeTab} onTabChange={setActiveTab} />

      <main className="main-content">
        {activeTab === "scanner" && <ScannerTab />}
        {activeTab === "redteam" && <RedTeamTab />}
        {activeTab === "audit" && <AuditTab />}
        {activeTab === "stats" && <StatsTab />}
        {activeTab === "developer" && <DeveloperTab />}
      </main>
    </div>
  );
}
