"use client"

import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import { ActivityFeedLive } from "@/components/dashboard/activity-feed-live"
import { ActiveMitigationsMini } from "@/components/dashboard/active-mitigations-mini"
import { MitigationActivityChart } from "@/components/dashboard/mitigation-activity-chart"
import { useMitigations } from "@/hooks/use-api"

export default function OverviewPage() {
  const { data, error, isLoading, mutate } = useMitigations({ status: ["active", "escalated"], limit: 50 })

  return (
    <DashboardLayout>
      <div className="mx-auto max-w-7xl space-y-6">
        <div>
          <h1 className="text-2xl font-semibold text-balance">Mitigation workspace</h1>
          <p className="mt-1 text-muted-foreground text-pretty">Review active intent, its signals and remaining lifetime.</p>
        </div>

        <BgpSessionStatus />

        <ActiveMitigationsMini
          mitigations={data?.mitigations ?? []}
          loading={isLoading}
          error={Boolean(error)}
          hasMore={data?.has_more}
          onRetry={() => { void mutate() }}
        />

        <section aria-label="History" className="grid gap-6 xl:grid-cols-2">
          <MitigationActivityChart />
          <ActivityFeedLive />
        </section>
      </div>
    </DashboardLayout>
  )
}
