import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";
import type { NotificationIntent } from "./notificationPolicy";

function isTauri(): boolean {
  return (
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
  );
}

export async function requestNotificationAccess(): Promise<boolean> {
  if (!isTauri()) return true;
  if (await isPermissionGranted()) return true;
  return (await requestPermission()) === "granted";
}

export async function showNativeNotification(
  intent: NotificationIntent,
): Promise<boolean> {
  if (!isTauri() || !(await isPermissionGranted())) return false;
  sendNotification({
    title: intent.title,
    body: intent.body,
  });
  return true;
}
