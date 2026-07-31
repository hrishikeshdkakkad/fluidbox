import { redirect } from "next/navigation";

export default function NewAgent() {
  redirect("/app?action=new-agent");
}
