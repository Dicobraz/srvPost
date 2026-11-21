/*
  Данные календаря (WEB-06): TanStack Query поверх JMAP — календари (Calendar/get), события
  видимого периода (CalendarEvent/query с развёрткой повторов + CalendarEvent/get кусками,
  капабилити calendars), справочник участников/комнат (Principal/query+get, капабилити
  principals) и своя занятость (Principal/getAvailability, капабилити availability — узел
  без хранилища занятости её не объявляет, подсветка просто не включается). Мутации —
  CalendarEvent/set с sendSchedulingMessages: сервер сам рассылает приглашения iTIP
  (REQUEST при создании, UPDATE при правке, CANCEL при отмене — tp-dav itip::plan).
*/

import { useMutation, useQuery } from "@tanstack/react-query";

import {
  CAP_AVAILABILITY,
  CAP_CALENDARS,
  CAP_ITIP,
  CAP_PRINCIPALS,
  calendarEventSet,
  calendarEventsInRange,
  calendarsGet,
  hasCapability,
  principalAvailability,
  principalGet,
  principalsByType,
  type BusyPeriod,
  type CalendarEventObject,
  type CalendarObject,
  type PrincipalObject,
} from "../api/jmap";
import { queryClient, keys } from "../mail/client";
import { useJmap } from "../mail/context";
import type { JmapEnv } from "../mail/types";

/** Есть ли календари у почтовой учётной записи (по сессии, без запроса). */
export function hasCalendars(env: JmapEnv): boolean {
  return hasCapability(env.session, env.accountId, CAP_CALENDARS);
}

/** Отправляет ли узел приглашения (планирование подключено): кнопки формы и ответов. */
export function hasScheduling(env: JmapEnv): boolean {
  return hasCapability(env.session, env.accountId, CAP_ITIP);
}

/** Учётная запись календарей (primaryAccounts[calendars]; совпадает с почтовой). */
function calendarAccountId(env: JmapEnv): string {
  return env.session.primaryAccounts[CAP_CALENDARS] ?? env.accountId;
}

/** Свои и подписанные календари: цвета чипов по calendarIds события. */
export function useCalendars(): CalendarObject[] {
  const env = useJmap();
  const enabled = hasCalendars(env);
  const query = useQuery<CalendarObject[]>({
    queryKey: keys.calendars(),
    queryFn: () => calendarsGet(env.apiUrl, env.authorization, calendarAccountId(env)).then((r) => r.list),
    enabled,
  });
  return enabled ? query.data ?? [] : [];
}

/** Цвет события: цвет его календаря; без цвета — фирменная синяя палитра чипа (макет 01). */
export function colorOfEvent(calendars: CalendarObject[], event: CalendarEventObject): string {
  const id = Object.keys(event.calendarIds ?? {})[0];
  const cal = calendars.find((c) => c.id === id);
  return cal?.color ?? "var(--cal-default, #4687d8)";
}

/** События видимого периода (после/до — ISO UTCDate). */
export function useCalendarEvents(after: string, before: string): CalendarEventObject[] {
  const env = useJmap();
  const enabled = hasCalendars(env);
  const query = useQuery<CalendarEventObject[]>({
    queryKey: keys.calendarEvents(after, before),
    queryFn: () =>
      calendarEventsInRange(env.apiUrl, env.authorization, calendarAccountId(env), after, before),
    enabled,
  });
  return enabled ? query.data ?? [] : [];
}

/** Справочник формы встречи: люди (individual), комнаты (location), оборудование (resource).
 * Нет капабилити principals — пусто (ввод адреса руками работает всегда). */
export function useDirectory(type: PrincipalObject["type"]): PrincipalObject[] {
  const env = useJmap();
  const enabled = hasCapability(env.session, env.accountId, CAP_PRINCIPALS);
  const query = useQuery<PrincipalObject[]>({
    queryKey: keys.directory(type),
    queryFn: () => principalsByType(env.apiUrl, env.authorization, env.accountId, type),
    enabled,
    staleTime: 5 * 60_000,
  });
  return enabled ? query.data ?? [] : [];
}

/** Своя занятость периода (read-only, подсветка занятых слотов формы). */
export function useOwnBusy(
  principalId: string | null,
  after: string,
  before: string,
): BusyPeriod[] {
  const env = useJmap();
  const enabled = Boolean(principalId) && hasCapability(env.session, env.accountId, CAP_AVAILABILITY);
  const query = useQuery<BusyPeriod[]>({
    queryKey: keys.busy(principalId ?? "", after, before),
    queryFn: () =>
      principalAvailability(env.apiUrl, env.authorization, env.accountId, principalId as string, after, before),
    enabled,
  });
  return enabled ? query.data ?? [] : [];
}

/** Свой участник (Principal/get по своей учётной записи — currentUserPrincipalId). */
export function useSelfPrincipal(): PrincipalObject | null {
  const env = useJmap();
  const enabled = hasCapability(env.session, env.accountId, CAP_PRINCIPALS);
  const query = useQuery<PrincipalObject | null>({
    queryKey: keys.selfPrincipal(),
    queryFn: () =>
      principalGet(env.apiUrl, env.authorization, env.accountId, [env.accountId]).then(
        (list) => list[0] ?? null,
      ),
    enabled,
    staleTime: 5 * 60_000,
  });
  return enabled ? query.data ?? null : null;
}

function invalidateCalendar(): void {
  void queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
  void queryClient.invalidateQueries({ queryKey: ["busy"] });
  void queryClient.invalidateQueries({ queryKey: ["calendars"] });
}

/** Свойства участника вхождения для формы: имя и адрес (mailto) из справочника. */
function participantOf(p: { name: string; email: string }): Record<string, unknown> {
  return {
    "@type": "Participant",
    name: p.name,
    calendarAddress: `mailto:${p.email}`,
    roles: { attendee: true },
    participationStatus: "needs-action",
    expectReply: true,
  };
}

/** Аргументы создания встречи: тема, время, участники, комната — JSCalendar из формы. */
export interface MeetingInput {
  title: string;
  /** LocalDateTime «YYYY-MM-DDTHH:MM:SS» в поясе timeZone. */
  start: string;
  timeZone: string;
  /** ISO 8601 duration (PT1H30M). */
  duration: string;
  description: string | null;
  /** Участники — приглашённые (адреса mailto). */
  attendees: Array<{ name: string; email: string }>;
  /** Комната (учётная запись-помещение): участник-ресурс + место встречи. */
  room: { name: string; email: string } | null;
}

/** JSCalendar-объект из формы: организатор — сам (адрес входа), участники и комната. */
export function meetingCreate(input: MeetingInput, self: { name: string; email: string }): Record<string, unknown> {
  const participants: Record<string, unknown> = {
    o: {
      "@type": "Participant",
      name: self.name || self.email,
      calendarAddress: `mailto:${self.email}`,
      roles: { owner: true },
    },
  };
  input.attendees.forEach((p, i) => {
    participants[`a${i}`] = participantOf(p);
  });
  if (input.room) {
    participants["room"] = participantOf(input.room);
  }
  const locations = input.room ? { r: { name: input.room.name } } : undefined;
  const event: Record<string, unknown> = {
    title: input.title,
    start: input.start,
    timeZone: input.timeZone,
    duration: input.duration,
    participants,
    ...(locations ? { locations } : {}),
    ...(input.description ? { description: input.description } : {}),
  };
  return event;
}

/** Патч правки из формы (всё поле целиком — сервер применяет патчи JSON Pointer). */
export function meetingUpdate(input: MeetingInput, self: { name: string; email: string }): Record<string, unknown> {
  return {
    title: input.title,
    start: input.start,
    timeZone: input.timeZone,
    duration: input.duration,
    description: input.description,
    participants: meetingCreate(input, self).participants,
    ...(input.room ? { locations: { r: { name: input.room.name } } } : { locations: null }),
  };
}

/** Создание встречи: CalendarEvent/set create + рассылка приглашений (sendSchedulingMessages —
 * узел без планирования её не даёт; событие запишется без рассылки). */
export function useMeetingCreateMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ input, self }: { input: MeetingInput; self: { name: string; email: string } }) => {
      const send = hasScheduling(env);
      const result = await calendarEventSet(
        env.apiUrl,
        env.authorization,
        calendarAccountId(env),
        { create: { m: meetingCreate(input, self) } },
        send,
      );
      const created = result.created["m"];
      if (!created?.id) {
        const error = result.errors["m"] as { description?: string; type?: string } | undefined;
        throw new Error(error?.description ?? error?.type ?? "Сервер не создал встречу.");
      }
      return created.id as string;
    },
    onSettled: () => invalidateCalendar(),
  });
}

/** Правка встречи (UPDATE участникам — рассылку делает сервер). */
export function useMeetingUpdateMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ id, input, self }: { id: string; input: MeetingInput; self: { name: string; email: string } }) => {
      const send = hasScheduling(env);
      const result = await calendarEventSet(
        env.apiUrl,
        env.authorization,
        calendarAccountId(env),
        { update: { [id]: meetingUpdate(input, self) } },
        send,
      );
      if (!result.updated?.[id] && result.errors[id]) {
        const error = result.errors[id] as { description?: string; type?: string } | undefined;
        throw new Error(error?.description ?? error?.type ?? "Сервер не изменил встречу.");
      }
      return id;
    },
    onSettled: () => invalidateCalendar(),
  });
}

/** Отмена встречи: destroy + sendSchedulingMessages — сервер рассылает CANCEL участникам. */
export function useMeetingCancelMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async (id: string) => {
      const result = await calendarEventSet(
        env.apiUrl,
        env.authorization,
        calendarAccountId(env),
        { destroy: [id] },
        hasScheduling(env),
      );
      if (!result.destroyed.includes(id)) {
        const error = result.errors[id] as { description?: string; type?: string } | undefined;
        throw new Error(error?.description ?? error?.type ?? "Сервер не отменил встречу.");
      }
      return id;
    },
    onSettled: () => invalidateCalendar(),
  });
}
