"use client"

import { cn } from "@/lib/utils"

interface StatusBadgeProps {
  status: "pending" | "active" | "escalated" | "expired" | "withdrawn" | "rejected"
  size?: "sm" | "default"
}

export function StatusBadge({ status, size = "default" }: StatusBadgeProps) {
  const isPositive = status === "active"
  const isNegative = status === "escalated" || status === "rejected"
  const isPending = status === "pending"
  const isInactive = status === "expired" || status === "withdrawn"


  return (
    <span
      className={cn(
        "inline-flex items-center rounded-sm border font-medium",
        size === "sm" ? "px-1.5 py-0.5 text-xs" : "px-2 py-1 text-xs",
        isPositive && "border-primary/50 text-primary bg-primary/5",
        isNegative && "border-destructive/50 text-destructive bg-destructive/5",
        isPending && "border-warning/50 text-warning bg-warning/5",
        isInactive && "border-border text-muted-foreground bg-muted/50",
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "mr-1.5 size-1.5 rounded-full",
          isPositive && "bg-primary",
          isNegative && "bg-destructive",
          isPending && "bg-warning",
          isInactive && "bg-muted-foreground",
        )}
      />
      {status}
    </span>
  )
}
