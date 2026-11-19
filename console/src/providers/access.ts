// Роли администраторов (SRS 5.2) в консоли: разделы меню и кнопки по ролям из `whoami`. Права проверяет узел —
// консоль лишь не показывает то, на что узел ответит отказом.
import { type AccessControlProvider, useCan } from "@refinedev/core";

import { type Schemas, whoami } from "../api/client";

type Role = Schemas["AdminRole"];

const WRITE = ["create", "edit", "delete", "clone"];
/** Журналы аудита: операций администраторов и доступа к ящикам. */
const AUDIT = ["audit", "mailbox-audit"];

/**
 * Роли допускают действие с разделом: аудитор — только чтение журналов аудита, оператор — чтение без журналов
 * аудита; изменять (политику аудита ящиков) — администратор организации. Журнал переписки (SRS 4.9, 5.2) —
 * только роли «аудитор журнала»: администраторам установки и организации узел ответит отказом; эта роль,
 * наоборот, кроме журнала ничего не видит.
 */
export function allowed(roles: Role[], resource: string | undefined, action: string) {
  if (resource === "journal") return roles.includes("journal_auditor");
  const admin = roles.includes("installation_admin") || roles.includes("organization_admin");
  if (!resource || admin) return true;
  if (roles.includes("journal_auditor")) return false;
  if (WRITE.includes(action)) return false;
  return AUDIT.includes(resource) ? roles.includes("auditor") : roles.includes("operator");
}

export const accessControlProvider: AccessControlProvider = {
  can: async ({ resource, action }) => {
    try {
      return { can: allowed((await whoami()).roles, resource, action) };
    } catch {
      return { can: true }; // роли неизвестны — решает узел
    }
  },
  options: { buttons: { enableAccessControl: true, hideIfUnauthorized: true } },
};

/** Раздел только для чтения (оператор, аудитор): кнопки изменения не показываются. */
export function useReadOnly(resource: string) {
  return useCan({ resource, action: "edit" }).data?.can === false;
}
