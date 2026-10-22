"use client"

import { useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/hooks/use-auth"
import { useHealth } from "@/hooks/use-api"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { User, LogOut, Shield, Loader2, Settings } from "lucide-react"
import { NotificationPreferencesPanel } from "@/components/dashboard/notification-preferences"
import { DisplayPreferencesPanel } from "@/components/dashboard/display-preferences"

export function UserMenu() {
  const { operator, logout, isLoading: authLoading } = useAuth()
  const { data: health, isLoading: healthLoading } = useHealth()
  const router = useRouter()
  const [isLoggingOut, setIsLoggingOut] = useState(false)
  const [showPrefs, setShowPrefs] = useState(false)
  const preferencesTrigger = useRef<HTMLButtonElement | null>(null)

  const namedOperator = !authLoading && !healthLoading && health && health.auth_mode !== "none" ? operator : null

  const handleLogout = async () => {
    setIsLoggingOut(true)

    try {
      await logout()
      router.push("/login")
    } finally {
      setIsLoggingOut(false)
    }
  }

  if (authLoading || healthLoading) {
    return <Skeleton role="status" aria-label="Loading operator menu" className="size-11 sm:size-9" />
  }

  return (
    <>
      {namedOperator ? <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button ref={preferencesTrigger} variant="ghost" size="sm" className="h-11 gap-2 sm:h-8" aria-label={`Operator menu for ${namedOperator.username}`}>
            <User className="h-4 w-4" />
            <span className="hidden max-w-32 truncate sm:inline">{namedOperator.username}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium">{namedOperator.username}</p>
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <Shield className="h-3 w-3" />
                {namedOperator.role}
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setShowPrefs(true)}>
            <Settings className="mr-2 h-4 w-4" />
            Preferences
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleLogout} disabled={isLoggingOut}>
            {isLoggingOut ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <LogOut className="mr-2 h-4 w-4" />
            )}
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu> : <Button ref={preferencesTrigger} variant="ghost" className="size-11 p-0 sm:size-9" aria-label="Preferences" onClick={() => setShowPrefs(true)}>
        <Settings className="size-4" aria-hidden="true" />
      </Button>}
      <Dialog open={showPrefs} onOpenChange={setShowPrefs}>
        <DialogContent className="max-h-[85dvh] overflow-y-auto sm:max-w-lg" onCloseAutoFocus={(event) => {
          event.preventDefault()
          preferencesTrigger.current?.focus()
        }}>
          <DialogHeader>
            <DialogTitle className="text-sm">Preferences</DialogTitle>
            <DialogDescription>
              Display settings stay in this browser.{namedOperator ? " Notifications are saved to your account." : ""}
            </DialogDescription>
          </DialogHeader>
          <DisplayPreferencesPanel />
          {namedOperator && <NotificationPreferencesPanel />}
        </DialogContent>
      </Dialog>
    </>
  )
}
