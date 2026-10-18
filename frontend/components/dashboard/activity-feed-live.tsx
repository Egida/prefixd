"use client"

import Link from "next/link"
import { Shield, AlertTriangle, User, FileText, AlertCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import { useEvents, useAuditLog } from "@/hooks/use-api"
import { Skeleton } from "@/components/ui/skeleton"

interface ActivityItem {
  id: string
  type: "mitigation" | "event" | "operator" | "system"
  timestamp: string
  description: string
  ip?: string
  href?: string
}

function formatTimestamp(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)

  if (diffMins < 1) return "just now"
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })
}

function getActivityIcon(type: ActivityItem["type"]) {
  switch (type) {
    case "mitigation":
      return <Shield className="h-3 w-3" />
    case "event":
      return <AlertTriangle className="h-3 w-3" />
    case "operator":
      return <User className="h-3 w-3" />
    case "system":
      return <FileText className="h-3 w-3" />
  }
}

export function ActivityFeedLive() {
  const { data: eventsResp, error: eventsError, isLoading: eventsLoading } = useEvents({ limit: 10 })
  const { data: auditResp, error: auditError, isLoading: auditLoading } = useAuditLog({ limit: 10 })
  const events = eventsResp?.events
  const audit = auditResp?.entries

  const isLoading = eventsLoading || auditLoading
  const hasError = eventsError || auditError

  // Combine and sort activities
  const activities: ActivityItem[] = []

  if (events) {
    for (const event of events.slice(0, 5)) {
      activities.push({
        id: `event-${event.event_id}`,
        type: "event",
        timestamp: event.ingested_at,
        description: `${event.vector.replace("_", " ")} detected from ${event.source}`,
        ip: event.victim_ip,
        href: `/events?id=${encodeURIComponent(event.event_id)}`,
      })
    }
  }

  if (audit) {
    for (const entry of audit.slice(0, 5)) {
      const actorType = entry.actor_type === "operator" ? "operator" : 
                        entry.actor_type === "system" ? "system" : "mitigation"
      
      let description = entry.action.replace(/_/g, " ")
      if (entry.target_id) {
        const shortId = entry.target_id.length > 8 ? entry.target_id.slice(0, 8) : entry.target_id
        description = `${description} (${shortId}...)`
      }

      const href = entry.target_type === "mitigation" && entry.target_id
        ? `/mitigations/${entry.target_id}`
        : undefined

      activities.push({
        id: `audit-${entry.audit_id}`,
        type: actorType,
        timestamp: entry.timestamp,
        description,
        ip: entry.details?.victim_ip as string | undefined,
        href,
      })
    }
  }

  // Sort by timestamp descending
  activities.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  const displayActivities = activities.slice(0, 10)

  if (hasError) {
    return (
      <div className="min-w-0">
        <h3 className="font-medium mb-3 text-balance">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <AlertCircle className="h-6 w-6 mb-2 text-destructive" />
          <p className="text-sm">Failed to load activity</p>
        </div>
      </div>
    )
  }

  if (isLoading && displayActivities.length === 0) {
    return (
      <div className="min-w-0">
        <h3 className="font-medium mb-3 text-balance">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <Skeleton className="mb-3 h-8 w-full" />
          <p role="status" className="text-sm">Loading activity…</p>
        </div>
      </div>
    )
  }

  if (displayActivities.length === 0) {
    return (
      <div className="min-w-0">
        <h3 className="font-medium mb-3 text-balance">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <p className="text-sm">No recent activity</p>
          <Link href="/audit-log" className="mt-2 rounded-sm text-primary hover:underline">View audit log</Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-w-0">
      <h3 className="font-medium mb-3 text-balance">Recent Activity</h3>
      <div className="space-y-0">
        {displayActivities.map((activity, index) => {
          const content = (
            <div
              key={activity.id}
              className={cn(
                "flex items-start gap-3 py-2 hover:bg-secondary/50",
                index !== displayActivities.length - 1 && "border-b border-border/50",
                activity.href && "cursor-pointer"
              )}
            >
              <div className="mt-0.5 opacity-60">{getActivityIcon(activity.type)}</div>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px]">
                  <span className="font-mono text-xs text-muted-foreground whitespace-nowrap tabular-nums">
                    {formatTimestamp(activity.timestamp)}
                  </span>
                  <span className="text-foreground text-pretty">{activity.description}</span>
                </div>
                {activity.ip && <span className="font-mono text-xs text-primary">{activity.ip}</span>}
              </div>
            </div>
          )

          return activity.href ? (
            <Link key={activity.id} href={activity.href} className="block rounded-sm">
              {content}
            </Link>
          ) : (
            <div key={activity.id}>{content}</div>
          )
        })}
      </div>
    </div>
  )
}
