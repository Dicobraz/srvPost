/*
  Раздел «Календарь» (WEB-06) — просмотр (день / рабочая неделя / неделя / месяц, PARITY
  calendar.*) и приём встреч. Данные — JMAP-календари (draft-ietf-jmap-calendars):
  Calendar/get и CalendarEvent/query с развёрткой повторов + CalendarEvent/get (calendar/
  client.ts); живое обновление — push Calendar/CalendarEvent в уже открытом WS-канале
  (calendar/sync.ts). Создание простой встречи (тема, время, участники и комната — из
  справочника Principal) и правка/отмена — CalendarEvent/set с рассылкой iTIP сервером;
  своя занятость (principals:availability) подсвечивает занятые слоты в форме.
  Планировочная сетка — свои div+grid на токенах макета 01 (без календарных библиотек),
  чипы — цветом календаря события. Панели — inline (не модалки), как в DESIGN.md Postman.
*/
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";

import type { CalendarEventObject } from "../api/jmap";
import {
  hasCalendars,
  hasScheduling,
  colorOfEvent,
  useCalendars,
  useCalendarEvents,
  useDirectory,
  useMeetingCancelMutation,
  useMeetingCreateMutation,
  useMeetingUpdateMutation,
  useOwnBusy,
  useSelfPrincipal,
} from "../calendar/client";
import {
  dayColumnTitle,
  dateInputValue,
  draftDurationMinutes,
  eventTimeLabel,
  fromDateTime,
  hourLabel,
  layoutTimed,
  localTimeZone,
  minutesToDuration,
  monthDayLabel,
  occurrencesOfDay,
  overlapsBusy,
  periodDayList,
  periodTitle,
  shiftAnchor,
  timeInputValue,
  toOccurrences,
  VIEW_LABELS,
  type CalendarViewKind,
  type MeetingDraft,
  type Occurrence,
} from "../calendar/model";
import { Icon } from "../mail/icons";
import { useJmap } from "../mail/context";
import { useToast } from "../mail/toast";
import { RecipientsField } from "../compose/RecipientsField";
import type { Recipient, Suggestion } from "../compose/recipients";
import type { PrincipalObject } from "../api/jmap";

/** Панель справа: форма встречи или детали выбранной встречи. */
type Panel =
  | { kind: "form"; draft: MeetingDraft; editingId: string | null }
  | { kind: "details"; occurrence: Occurrence }
  | null;

const HOUR_PX = 48;
const HOURS = Array.from({ length: 24 }, (_, i) => i);

/** «#rrggbb» → «rgba(r,g,b,a)» для подложки чипа; нецвет — null (подложка классом). */
function tintOf(color: string, alpha: number): string | null {
  const m = /^#([0-9a-f]{6})$/i.exec(color.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
}

/** Стиль чипа по цвету календаря: полоса слева и прозрачная подложка (макет 01). */
function chipStyle(color: string): { borderLeft: string; background: string } {
  return {
    borderLeft: `3px solid ${color}`,
    background: tintOf(color, 0.16) ?? "var(--cal-tint, rgba(70, 135, 216, 0.16))",
  };
}

/** ISO UTCDate границ периода (после — начало, до — конец; серверный интервал [after, before)). */
function isoBounds(kind: CalendarViewKind, anchor: Date): { after: string; before: string } {
  const days = periodDayList(kind, anchor);
  const start = days[0];
  const end = new Date(start.getTime() + days.length * 24 * 3_600_000);
  return { after: start.toISOString(), before: end.toISOString() };
}

/** Начало суток в миллисекундах (ключ дня в картах). */
function startOfDayMs(d: Date): number {
  const out = new Date(d);
  out.setHours(0, 0, 0, 0);
  return out.getTime();
}

export function CalendarPage() {
  const env = useJmap();
  const toast = useToast();
  const [params, setParams] = useSearchParams();
  const [view, setView] = useState<CalendarViewKind>("workweek");
  const [anchor, setAnchor] = useState<Date>(() => new Date());
  const [panel, setPanel] = useState<Panel>(null);
  // Скрытые календари (панель «Календари») — показ по умолчанию у всех.
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  // Участники и комната формы — состояние страницы (сохранение берёт отсюда).
  const [formAttendees, setFormAttendees] = useState<Recipient[]>([]);
  const [formRoom, setFormRoom] = useState<string>("");

  // «Встреча с контактом» (WEB-07): карточка контакта передаёт участника параметрами маршрута
  // (?attendee=…&attendeeName=…) — форма создания открывается сразу с этим участником;
  // параметры снимаются, чтобы повторный заход не открывал форму снова.
  const attendee = params.get("attendee");
  const attendeeName = params.get("attendeeName");
  const consumed = useRef(false);
  useEffect(() => {
    if (!attendee || consumed.current) return;
    consumed.current = true;
    const start = new Date();
    start.setHours(9, 0, 0, 0);
    setFormAttendees([{ name: attendeeName || null, email: attendee }]);
    setFormRoom("");
    setPanel({
      kind: "form",
      editingId: null,
      draft: {
        title: "",
        date: dateInputValue(start),
        start: timeInputValue(start),
        end: timeInputValue(new Date(start.getTime() + 60 * 60_000)),
        description: "",
      },
    });
    setParams({}, { replace: true });
  }, [attendee, attendeeName, setParams]);

  const calendars = useCalendars();
  const self = useSelfPrincipal();
  const rooms = useDirectory("location");
  const people = useDirectory("individual");
  const bounds = useMemo(() => isoBounds(view, anchor), [view, anchor]);
  const events = useCalendarEvents(bounds.after, bounds.before);
  const busy = useOwnBusy(self?.id ?? null, bounds.after, bounds.before);

  const create = useMeetingCreateMutation();
  const update = useMeetingUpdateMutation();
  const cancel = useMeetingCancelMutation();

  const now = new Date();
  const colorOf = useMemo(
    () => (event: CalendarEventObject) => colorOfEvent(calendars, event),
    [calendars],
  );
  const occurrences = useMemo(
    () =>
      toOccurrences(events, colorOf).filter((o) => {
        const ids = Object.keys(o.event.calendarIds ?? {});
        return ids.length === 0 || ids.some((id) => !hidden.has(id));
      }),
    [events, colorOf, hidden],
  );

  const days = useMemo(() => periodDayList(view, anchor), [view, anchor]);
  const byDay = useMemo(
    () => new Map(days.map((d) => [d.getTime(), occurrencesOfDay(occurrences, d)])),
    [days, occurrences],
  );
  const busyByDay = useMemo(() => {
    // Занятость раскладывается по всем суткам, которые период пересекает (встреча через
    // полночь видна и в предыдущем дне, и в следующем).
    const map = new Map<number, Array<{ utcStart: string; utcEnd: string; busyStatus: string }>>();
    for (const b of busy) {
      const from = new Date(b.utcStart).getTime();
      const to = new Date(b.utcEnd).getTime();
      for (let day = startOfDayMs(new Date(from)); day < to; day = startOfDayMs(new Date(day + 24 * 3_600_000))) {
        map.set(day, [...(map.get(day) ?? []), b]);
      }
    }
    return map;
  }, [busy]);

  const openCreate = (day?: Date) => {
    // Двойной клик по дню/кнопка «Создать» — черновик с 9:00 этого дня (как в Outlook).
    const base = day ?? anchor;
    const start = new Date(base);
    start.setHours(9, 0, 0, 0);
    const end = new Date(start.getTime() + 60 * 60_000);
    setFormAttendees([]);
    setFormRoom("");
    setPanel({
      kind: "form",
      editingId: null,
      draft: {
        title: "",
        date: dateInputValue(start),
        start: timeInputValue(start),
        end: timeInputValue(end),
        description: "",
      },
    });
  };

  const openEdit = (o: Occurrence) => {
    setFormAttendees(
      Object.values(o.event.participants ?? {})
        .filter((p) => !p.roles?.owner && p.calendarAddress && p.calendarAddress !== `mailto:${self?.email ?? env.selfAddress}`)
        .map((p) => ({
          name: p.name ?? null,
          email: (p.calendarAddress ?? "").replace(/^mailto:/, ""),
        }))
        .filter((r) => r.email),
    );
    const roomName = o.event.locations ? Object.values(o.event.locations)[0]?.name : null;
    const room = rooms.find((r) => r.name === roomName);
    setFormRoom(room?.id ?? "");
    setPanel({
      kind: "form",
      editingId: o.event.id,
      draft: {
        title: o.event.title ?? "",
        date: dateInputValue(o.start),
        start: timeInputValue(o.start),
        end: timeInputValue(o.end),
        description: o.event.description ?? "",
      },
    });
  };

  const saveForm = async (draft: MeetingDraft, editingId: string | null) => {
    const email = self?.email ?? env.selfAddress;
    const name = self?.name ?? email;
    const room = rooms.find((r) => r.id === formRoom) ?? null;
    const input = {
      title: draft.title.trim(),
      start: `${draft.date}T${draft.start}:00`,
      timeZone: localTimeZone(),
      duration: minutesToDuration(draftDurationMinutes(draft)),
      description: draft.description.trim() || null,
      attendees: formAttendees.map((r) => ({ id: r.email, name: r.name ?? r.email, email: r.email })),
      room,
    };
    try {
      if (editingId) {
        await update.mutateAsync({ id: editingId, input, self: { name, email } });
        toast.show("Встреча изменена — участникам уйдут обновления");
      } else {
        await create.mutateAsync({ input, self: { name, email } });
        toast.show(
          input.attendees.length + (input.room ? 1 : 0) > 0 && hasScheduling(env)
            ? "Встреча создана — приглашения отправлены"
            : "Встреча создана",
        );
      }
      setPanel(null);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не сохранил встречу");
    }
  };

  // Выбранная встреча актуализируется живыми данными (push мог её изменить или удалить).
  const panelOccurrence =
    panel?.kind === "details"
      ? occurrences.find((o) => o.event.id === panel.occurrence.event.id) ?? null
      : null;

  if (!hasCalendars(env)) {
    return (
      <section className="cal" aria-label="Календарь">
        <div className="cal-empty">
          <h1>Календарь</h1>
          <p>На этом узле нет календарей (капабилити calendars не объявлена).</p>
        </div>
      </section>
    );
  }

  return (
    <section className="cal" aria-label="Календарь">
      <div className="cal-cmd">
        <button type="button" className="btn-acc" onClick={() => openCreate()}>
          <Icon name="pen" size={16} />
          Создать встречу
        </button>
        <div className="cal-views" role="tablist" aria-label="Вид календаря">
          {(Object.keys(VIEW_LABELS) as CalendarViewKind[]).map((k) => (
            <button
              key={k}
              type="button"
              role="tab"
              aria-selected={view === k}
              className={`cal-view${view === k ? " on" : ""}`}
              onClick={() => setView(k)}
            >
              {VIEW_LABELS[k]}
            </button>
          ))}
        </div>
        <div className="cal-nav">
          <button
            type="button"
            className="cal-arrow"
            aria-label="Предыдущий период"
            onClick={() => setAnchor(shiftAnchor(view, anchor, -1))}
          >
            ‹
          </button>
          <button type="button" className="cal-today" onClick={() => setAnchor(new Date())}>
            Сегодня
          </button>
          <button
            type="button"
            className="cal-arrow"
            aria-label="Следующий период"
            onClick={() => setAnchor(shiftAnchor(view, anchor, 1))}
          >
            ›
          </button>
        </div>
        <h2 className="cal-title">{periodTitle(view, anchor)}</h2>
        <span className="sp" />
      </div>
      <div className="cal-main">
        <aside className="cal-side" aria-label="Мои календари">
          <div className="cal-side-cap">Календари</div>
          {calendars.map((c) => (
            <label key={c.id} className="cal-item">
              <input
                type="checkbox"
                checked={!hidden.has(c.id)}
                onChange={(e) => {
                  const next = new Set(hidden);
                  if (e.target.checked) next.delete(c.id);
                  else next.add(c.id);
                  setHidden(next);
                }}
                aria-label={`Показывать календарь ${c.name}`}
              />
              <span
                className="cal-dot"
                style={{ background: c.color ?? "var(--cal-default, #4687d8)" }}
              />
              <span className="cal-name">{c.name}</span>
              {c.isSubscribed && <span className="cal-tag">подписка</span>}
            </label>
          ))}
          {calendars.length === 0 && <div className="cal-side-note">Календарей пока нет</div>}
        </aside>
        <div className="cal-card">
          {view === "month" ? (
            <MonthGrid days={days} byDay={byDay} now={now} month={anchor.getMonth()} onSelect={setPanel} />
          ) : (
            <TimeGrid
              days={days}
              byDay={byDay}
              busyByDay={busyByDay}
              now={now}
              onSelect={setPanel}
              onOpenCreate={openCreate}
            />
          )}
        </div>
        {panel?.kind === "form" && (
          <MeetingPanel
            draft={panel.draft}
            editingId={panel.editingId}
            people={people}
            rooms={rooms}
            busyForDay={busyByDay.get(startOfDayMs(fromDateTime(panel.draft.date, "00:00"))) ?? []}
            saving={create.isPending || update.isPending}
            canInvite={hasScheduling(env)}
            attendees={formAttendees}
            onAttendees={setFormAttendees}
            room={formRoom}
            onRoom={setFormRoom}
            onClose={() => setPanel(null)}
            onSave={(draft) => void saveForm(draft, panel.editingId)}
          />
        )}
        {panel?.kind === "details" && panelOccurrence && (
          <DetailsPanel
            occurrence={panelOccurrence}
            canEdit={Boolean(panelOccurrence.event.isOrigin)}
            onCancel={async () => {
              try {
                await cancel.mutateAsync(panelOccurrence.event.id);
                toast.show("Встреча отменена — участникам уйдут уведомления");
                setPanel(null);
              } catch (e) {
                toast.show(e instanceof Error ? e.message : "Сервер не отменил встречу");
              }
            }}
            cancelling={cancel.isPending}
            onClose={() => setPanel(null)}
            onEdit={() => openEdit(panelOccurrence)}
          />
        )}
      </div>
    </section>
  );
}

// ---------- Сетка времени (день / рабочая неделя / неделя) ----------

interface GridProps {
  days: Date[];
  byDay: Map<number, Occurrence[]>;
  now: Date;
  onSelect(panel: Panel): void;
}

function TimeGrid({
  days,
  byDay,
  busyByDay,
  now,
  onSelect,
  onOpenCreate,
}: GridProps & {
  busyByDay: Map<number, Array<{ utcStart: string; utcEnd: string; busyStatus: string }>>;
  onOpenCreate(day: Date): void;
}) {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  // Рабочее утро в кадре при открытии (как в Outlook: сетка открывается с 8 утра).
  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = 8 * HOUR_PX;
  }, []);

  const todayMs = startOfDayMs(now);
  return (
    <div className="cal-timegrid">
      <div className="cal-thead" style={{ gridTemplateColumns: `56px repeat(${days.length}, minmax(0, 1fr))` }}>
        <div className="cal-corner" />
        {days.map((d) => {
          const t = dayColumnTitle(d, now);
          return (
            <div key={d.getTime()} className={`cal-dayhead${t.isToday ? " today" : ""}`}>
              <span className="wd">{t.weekday}</span>
              <span className="dt">{t.date}</span>
            </div>
          );
        })}
      </div>
      <div className="cal-allday" style={{ gridTemplateColumns: `56px repeat(${days.length}, minmax(0, 1fr))` }}>
        <div className="cal-allday-cap">Весь день</div>
        {days.map((d) => {
          const chips = (byDay.get(d.getTime()) ?? []).filter((o) => o.allDay);
          return (
            <div key={d.getTime()} className={`cal-allday-cell${startOfDayMs(d) === todayMs ? " today" : ""}`}>
              {chips.map((o) => (
                <button
                  key={o.event.id}
                  type="button"
                  className="cal-chip allday"
                  style={chipStyle(o.color)}
                  onClick={() => onSelect({ kind: "details", occurrence: o })}
                >
                  <span className="ttl">{o.event.title || "(без названия)"}</span>
                </button>
              ))}
            </div>
          );
        })}
      </div>
      <div className="cal-tbody" ref={scrollerRef}>
        <div
          className="cal-body"
          style={{ gridTemplateColumns: `56px repeat(${days.length}, minmax(0, 1fr))` }}
        >
          <div className="cal-hours">
            {HOURS.map((h) => (
              <div key={h} className="cal-hourlab" style={{ height: HOUR_PX }}>
                {hourLabel(h)}
              </div>
            ))}
          </div>
          {days.map((d) => {
            const dayMs = startOfDayMs(d);
            const chips = layoutTimed(byDay.get(dayMs) ?? [], d);
            const busy = busyByDay.get(dayMs) ?? [];
            const nowTop =
              dayMs === todayMs ? ((now.getTime() - dayMs) / (24 * 3_600_000)) * 100 : null;
            return (
              <div
                key={dayMs}
                className={`cal-daycol${dayMs === todayMs ? " today" : ""}`}
                style={{ height: HOURS.length * HOUR_PX }}
                onDoubleClick={() => onOpenCreate(d)}
              >
                {busy.map((b, i) => {
                  const s = new Date(b.utcStart);
                  const e = new Date(b.utcEnd);
                  const from = Math.max(s.getTime(), dayMs);
                  const to = Math.min(e.getTime(), dayMs + 24 * 3_600_000);
                  if (to <= from) return null;
                  return (
                    <div
                      key={i}
                      className="cal-busy"
                      style={{
                        top: `${((from - dayMs) / (24 * 3_600_000)) * 100}%`,
                        height: `${((to - from) / (24 * 3_600_000)) * 100}%`,
                      }}
                      title={`Занято: ${eventTimeLabel(s, e)}`}
                    />
                  );
                })}
                {nowTop !== null && (
                  <div
                    className="cal-nowline"
                    style={{ top: `${nowTop}%` }}
                    data-now={now.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}
                  />
                )}
                {chips.map((chip) => (
                  <button
                    key={chip.occurrence.event.id}
                    type="button"
                    className="cal-chip timed"
                    style={{
                      ...chipStyle(chip.occurrence.color),
                      top: `${chip.top}%`,
                      height: `${chip.height}%`,
                      left: `${(chip.lane / chip.lanes) * 100}%`,
                      width: `${(1 / chip.lanes) * 100}%`,
                    }}
                    onClick={() => onSelect({ kind: "details", occurrence: chip.occurrence })}
                  >
                    <span className="t">{eventTimeLabel(chip.occurrence.start, chip.occurrence.end)}</span>
                    <span className="ttl">{chip.occurrence.event.title || "(без названия)"}</span>
                  </button>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ---------- Сетка месяца ----------

function MonthGrid({
  days,
  byDay,
  now,
  month,
  onSelect,
}: GridProps & { month: number }) {
  const todayMs = startOfDayMs(now);
  return (
    <div className="cal-month">
      <div className="cal-month-head">
        {["пн", "вт", "ср", "чт", "пт", "сб", "вс"].map((w) => (
          <div key={w} className="cal-month-wd">
            {w}
          </div>
        ))}
      </div>
      <div className="cal-month-body">
        {chunk(days, 7).map((week, wi) => (
          <div key={wi} className="cal-month-row">
            {week.map((d) => {
              const dayMs = startOfDayMs(d);
              const list = byDay.get(dayMs) ?? [];
              const chips = list.slice(0, 3);
              return (
                <div
                  key={dayMs}
                  className={`cal-month-cell${dayMs === todayMs ? " today" : ""}${
                    d.getMonth() === month ? "" : " out"
                  }`}
                >
                  <div className="cal-month-day">{monthDayLabel(d)}</div>
                  {chips.map((o) => (
                    <button
                      key={o.event.id}
                      type="button"
                      className="cal-chip month"
                      style={chipStyle(o.color)}
                      onClick={() => onSelect({ kind: "details", occurrence: o })}
                    >
                      {!o.allDay && (
                        <span className="t">
                          {o.start.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}
                        </span>
                      )}
                      <span className="ttl">{o.event.title || "(без названия)"}</span>
                    </button>
                  ))}
                  {list.length > chips.length && (
                    <button
                      type="button"
                      className="cal-more"
                      onClick={() => onSelect({ kind: "details", occurrence: list[3] })}
                    >
                      Ещё {list.length - chips.length}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

function chunk<T>(list: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

// ---------- Панель встречи (форма) ----------

interface MeetingPanelProps {
  draft: MeetingDraft;
  editingId: string | null;
  /** Справочник формы: люди и комнаты (у страницы — общий кэш). */
  people: PrincipalObject[];
  rooms: PrincipalObject[];
  /** Своя занятость выбранного дня (read-only подсветка, principals:availability). */
  busyForDay: Array<{ utcStart: string; utcEnd: string; busyStatus: string }>;
  saving: boolean;
  canInvite: boolean;
  attendees: Recipient[];
  onAttendees(recipients: Recipient[]): void;
  room: string;
  onRoom(room: string): void;
  onClose(): void;
  onSave(draft: MeetingDraft): void;
}

function MeetingPanel({
  draft: initial,
  editingId,
  people,
  rooms,
  busyForDay,
  saving,
  canInvite,
  attendees,
  onAttendees,
  room,
  onRoom,
  onClose,
  onSave,
}: MeetingPanelProps) {
  const [draft, setDraft] = useState<MeetingDraft>(initial);
  const [error, setError] = useState<string | null>(null);
  const set = (patch: Partial<MeetingDraft>) => setDraft((d) => ({ ...d, ...patch }));

  const suggestions = useMemo<Suggestion[]>(
    () => people.map((p) => ({ recipient: { name: p.name, email: p.email }, source: "Справочник" })),
    [people],
  );

  const start = fromDateTime(draft.date, draft.start);
  const end = new Date(start.getTime() + draftDurationMinutes(draft) * 60_000);
  const conflict = overlapsBusy(start, end, busyForDay);

  const submit = () => {
    if (!draft.title.trim()) {
      setError("У встречи должна быть тема.");
      return;
    }
    setError(null);
    onSave(draft);
  };

  return (
    <aside className="cal-panel" aria-label={editingId ? "Изменение встречи" : "Новая встреча"}>
      <div className="cal-panel-head">
        <b>{editingId ? "Изменить встречу" : "Новая встреча"}</b>
        <button type="button" className="cal-x" aria-label="Закрыть панель" onClick={onClose}>
          <Icon name="x" size={16} />
        </button>
      </div>
      <div className="cal-panel-body">
        <label className="cal-field">
          <span>Тема</span>
          <input
            value={draft.title}
            onChange={(e) => set({ title: e.target.value })}
            placeholder="О чём встреча"
            autoFocus
          />
        </label>
        <div className="cal-field-row">
          <label className="cal-field">
            <span>Дата</span>
            <input type="date" value={draft.date} onChange={(e) => set({ date: e.target.value })} />
          </label>
          <label className="cal-field">
            <span>Начало</span>
            <input type="time" value={draft.start} onChange={(e) => set({ start: e.target.value })} />
          </label>
          <label className="cal-field">
            <span>Конец</span>
            <input type="time" value={draft.end} onChange={(e) => set({ end: e.target.value })} />
          </label>
        </div>
        <RecipientsField
          label="Участники"
          recipients={attendees}
          candidates={suggestions}
          onChange={onAttendees}
          placeholder="имя или адрес — из справочника"
        />
        {rooms.length > 0 && (
          <label className="cal-field">
            <span>Комната</span>
            <select value={room} onChange={(e) => onRoom(e.target.value)}>
              <option value="">Без комнаты</option>
              {rooms.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.email})
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="cal-field">
          <span>Описание</span>
          <textarea
            value={draft.description}
            onChange={(e) => set({ description: e.target.value })}
            rows={3}
            placeholder="Повестка, материалы"
          />
        </label>
        {busyForDay.length > 0 && (
          <div className="cal-busystrip">
            <div className="cal-busy-cap">Ваш день · занятость</div>
            <div className="cal-busy-bar">
              {busyForDay.map((b, i) => {
                const s = new Date(b.utcStart);
                const e = new Date(b.utcEnd);
                const top = ((s.getTime() - startOfDayMs(s)) / (24 * 3_600_000)) * 100;
                const height = Math.max(1, ((e.getTime() - s.getTime()) / (24 * 3_600_000)) * 100);
                return (
                  <div
                    key={i}
                    className="cal-busy"
                    style={{ top: `${top}%`, height: `${height}%` }}
                    title={`Занято: ${eventTimeLabel(s, e)}`}
                  />
                );
              })}
            </div>
            <div className="cal-busy-hours">
              <span>{hourLabel(0)}</span>
              <span>{hourLabel(12)}</span>
              <span>24:00</span>
            </div>
          </div>
        )}
        {conflict && (
          <div className="cal-warn" role="alert">
            ▲ Время пересекается с вашей занятостью
          </div>
        )}
        {error && (
          <div className="cal-warn" role="alert">
            ▲ {error}
          </div>
        )}
      </div>
      <div className="cal-panel-foot">
        <span className="cal-note">
          {canInvite
            ? attendees.length + (room ? 1 : 0) > 0
              ? "Приглашение уйдёт участникам через календарь сервера"
              : "Без участников — встреча только в вашем календаре"
            : "Планирование отключено на узле — встреча без приглашений"}
        </span>
        <span className="sp" />
        <button type="button" className="button" onClick={onClose}>
          Отмена
        </button>
        <button type="button" className="button button-primary" disabled={saving} onClick={submit}>
          {saving ? "Сохраняем…" : editingId ? "Сохранить" : "Создать"}
        </button>
      </div>
    </aside>
  );
}

// ---------- Панель деталей встречи ----------

const STATUS_LABELS: Record<string, string> = {
  accepted: "принял",
  declined: "отклонил",
  tentative: "под вопросом",
  "needs-action": "ждёт ответа",
  delegated: "перенаправил",
};

function DetailsPanel({
  occurrence,
  canEdit,
  onCancel,
  cancelling,
  onClose,
  onEdit,
}: {
  occurrence: Occurrence;
  canEdit: boolean;
  onCancel(): void;
  cancelling: boolean;
  onClose(): void;
  onEdit(): void;
}) {
  const [confirming, setConfirming] = useState(false);
  const e = occurrence.event;
  const location = e.locations ? Object.values(e.locations)[0]?.name : null;
  const participants = Object.values(e.participants ?? {});
  return (
    <aside className="cal-panel" aria-label="Встреча">
      <div className="cal-panel-head">
        <b>{e.title || "(без названия)"}</b>
        <button type="button" className="cal-x" aria-label="Закрыть панель" onClick={onClose}>
          <Icon name="x" size={16} />
        </button>
      </div>
      <div className="cal-panel-body">
        <div className="cal-when">{eventTimeLabel(occurrence.start, occurrence.end)}</div>
        <div className="cal-when muted">
          {occurrence.start.toLocaleDateString("ru", {
            weekday: "long",
            day: "numeric",
            month: "long",
            year: "numeric",
          })}
        </div>
        {location && <div className="cal-line">Место: {location}</div>}
        {e.organizerCalendarAddress && (
          <div className="cal-line">
            Организатор: {e.organizerCalendarAddress.replace(/^mailto:/, "")}
          </div>
        )}
        {e.description && <div className="cal-line">{e.description}</div>}
        {participants.length > 0 && (
          <div className="cal-people">
            <div className="cal-side-cap">Участники</div>
            {participants.map((p, i) => (
              <div key={i} className="cal-person">
                <span className="cal-person-name">
                  {p.name || p.calendarAddress?.replace(/^mailto:/, "") || "участник"}
                  {p.roles?.owner ? " · организатор" : ""}
                </span>
                <span className="chip">
                  {STATUS_LABELS[p.participationStatus ?? "needs-action"] ?? p.participationStatus}
                </span>
              </div>
            ))}
          </div>
        )}
        {canEdit ? (
          <div className="cal-actions">
            {confirming ? (
              <>
                <span className="cal-note">Отменить встречу и уведомить участников?</span>
                <span className="sp" />
                <button type="button" className="button" onClick={() => setConfirming(false)}>
                  Нет
                </button>
                <button
                  type="button"
                  className="button button-danger"
                  disabled={cancelling}
                  onClick={onCancel}
                >
                  {cancelling ? "Отменяем…" : "Да, отменить"}
                </button>
              </>
            ) : (
              <>
                <button type="button" className="button" onClick={onEdit}>
                  Изменить
                </button>
                <button
                  type="button"
                  className="button button-danger"
                  onClick={() => setConfirming(true)}
                >
                  Отменить встречу
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="cal-note">Править можно только свои встречи (вы участник).</div>
        )}
      </div>
    </aside>
  );
}
