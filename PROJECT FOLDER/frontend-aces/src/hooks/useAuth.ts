import { useNavigate } from "react-router-dom";

export function useHardBlock() {
  const nav = useNavigate();
  return () => {
    localStorage.clear();
    nav("/access-denied", { replace: true });
  };
}

export function checkBannedResponse(status: number, data: any, block: () => void): boolean {
  if (status === 403 || data?.banned) {
    block();
    return true;
  }
  return false;
}
