import { redirect } from "next/navigation";

export default function NewAgent() {
  redirect("/?action=new-agent");
}
