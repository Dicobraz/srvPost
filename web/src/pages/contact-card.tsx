/*
  Карточка контакта (WEB-07) — таб приложения (маршрут /contacts/:id, DESIGN.md: контакты —
  таб, не модалка): все поля (имя, адреса, телефоны, организация, должность, фото, заметки),
  книга с пометкой «справочник» для GAL, дата изменения. Действия (PARITY contacts.*):
  «Написать» (композер с получателем), «Встреча» (форма календаря с участником),
  «Копировать адрес» (буфер + тост), «Изменить» (панель формы), «Удалить», «В группу ▾»
  (добавить в группу рассылки). Книга GAL read-only: правка и удаление недоступны.
  Группа (kind=group) — участники с «убрать», поиск участника по своим контактам.
*/
import { useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router";

import { Icon } from "../mail/icons";
import { useToast } from "../mail/toast";
import {
  useBookById,
  useContactCard,
  useContactDelete,
  useContactSnapshot,
  useContactUpdate,
  useGroupMemberMutation,
  useGroupRename,
} from "../contacts/queries";
import {
  bookIdOf,
  bookWritable,
  emailsOf,
  fullNameOf,
  initials,
  isGroupCard,
  memberUidsOf,
  notesOf,
  organizationOf,
  phonesOf,
  photoUrlOf,
  primaryEmailOf,
  titleOf,
  type ContactCard,
  type ContactForm,
} from "../contacts/model";
import { CardEditor, formOf } from "../contacts/CardEditor";
import { copyText } from "../contacts/clipboard";

export function ContactCardPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const [params, setParams] = useSearchParams();

  const card = useContactCard(id);
  const bookOf = useBookById();
  const snapshot = useContactSnapshot();

  const update = useContactUpdate();
  const remove = useContactDelete();
  const member = useGroupMemberMutation();
  const renameGroup = useGroupRename();

  const book = bookOf(bookIdOf(card ?? {}) ?? null);
  // Книга «Организация» (GAL) и другие read-only: правка недоступна (сервер ответил бы forbidden).
  const writable = bookWritable(book);
  const group = card ? isGroupCard(card) : false;

  // Панель формы правки: параметр ?edit=1 из контекстного меню списка открывает её сразу.
  const [editing, setEditing] = useState(params.get("edit") === "1");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [groupMenu, setGroupMenu] = useState(false);
  const [memberQuery, setMemberQuery] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [groupDraft, setGroupDraft] = useState("");

  // Карточки по uid — участники группы (снимок: карточки учётной записи).
  const byUid = useMemo(() => new Map(snapshot.map((c) => [String(c.uid), c])), [snapshot]);
  const members = useMemo(
    () =>
      card
        ? memberUidsOf(card).flatMap((uid): ContactCard[] => {
            const member = byUid.get(uid);
            return member ? [member] : [];
          })
        : [],
    [card, byUid],
  );
  const missing = card ? memberUidsOf(card).filter((uid) => !byUid.has(uid)) : [];

  // Кандидаты в участники группы: свои карточки-контакты, ещё не в группе, по подстроке.
  const candidates = useMemo(() => {
    if (!card) return [];
    const inGroup = new Set(memberUidsOf(card));
    const q = memberQuery.trim().toLowerCase();
    return snapshot
      .filter((c) => !isGroupCard(c) && !inGroup.has(String(c.uid)))
      .filter((c) => {
        if (!q) return true;
        const name = fullNameOf(c).toLowerCase();
        const email = primaryEmailOf(c)?.toLowerCase() ?? "";
        return name.includes(q) || email.includes(q);
      })
      .slice(0, 12);
  }, [card, snapshot, memberQuery]);

  const groups = useMemo(() => snapshot.filter(isGroupCard), [snapshot]);

  const closeEditor = () => {
    setEditing(false);
    if (params.get("edit")) setParams({}, { replace: true });
  };

  const saveForm = async (form: ContactForm) => {
    if (!card) return;
    try {
      await update.mutateAsync({ id: String(card.id), form });
      setEditing(false);
      if (params.get("edit")) setParams({}, { replace: true });
      toast.show("Контакт сохранён");
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не сохранил контакт.");
    }
  };

  const write = () => {
    const email = card ? primaryEmailOf(card) : null;
    if (!email) {
      toast.show("У контакта нет адреса.");
      return;
    }
    const name = card ? fullNameOf(card) : "";
    navigate(`/compose?to=${encodeURIComponent(name ? `${name} <${email}>` : email)}`);
  };

  const meet = () => {
    const email = card ? primaryEmailOf(card) : null;
    if (!email) {
      toast.show("У контакта нет адреса для приглашения.");
      return;
    }
    const name = card ? fullNameOf(card) : "";
    navigate(
      `/calendar?attendee=${encodeURIComponent(email)}${
        name ? `&attendeeName=${encodeURIComponent(name)}` : ""
      }`,
    );
  };

  const copy = async () => {
    const email = card ? primaryEmailOf(card) : null;
    if (!email) {
      toast.show("У контакта нет адреса.");
      return;
    }
    toast.show((await copyText(email)) ? `Адрес скопирован: ${email}` : "Не удалось скопировать адрес.");
  };

  const destroy = async () => {
    if (!card) return;
    try {
      await remove.mutateAsync(String(card.id));
      toast.show(group ? "Группа удалена" : "Контакт удалён");
      navigate("/contacts");
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не удалил карточку.");
    }
  };

  const addToGroup = async (groupId: string, groupName: string) => {
    setGroupMenu(false);
    if (!card) return;
    try {
      await member.mutateAsync({ groupId, uid: String(card.uid), add: true });
      toast.show(`Добавлено в группу: ${groupName}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не обновил группу.");
    }
  };

  const removeFromGroup = async (uid: string) => {
    if (!card) return;
    try {
      await member.mutateAsync({ groupId: String(card.id), uid, add: false });
      toast.show("Участник убран из группы");
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не обновил группу.");
    }
  };

  const submitRename = async () => {
    const name = groupDraft.trim();
    if (!card || !name) return;
    try {
      await renameGroup.mutateAsync({ id: String(card.id), name });
      setRenaming(false);
      toast.show("Группа переименована");
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не переименовал группу.");
    }
  };

  if (!card) {
    return (
      <section className="stub" aria-busy="true">
        <h1>Контакты</h1>
        <p>{id ? "Загружаем карточку…" : "Карточка не выбрана."}</p>
      </section>
    );
  }

  const name = fullNameOf(card) || "(без имени)";
  const email = primaryEmailOf(card);
  const emails = emailsOf(card);
  const phones = phonesOf(card);
  const org = organizationOf(card);
  const title = titleOf(card);
  const photo = photoUrlOf(card);
  const notes = notesOf(card);
  const updated = typeof card.updated === "string" ? card.updated : null;

  return (
    <section className="mail contacts" aria-label="Карточка контакта">
      <div className="cmd">
        <button type="button" className="btn-q" onClick={() => navigate("/contacts")}>
          <Icon name="folder" size={16} />
          К контактам
        </button>
        {!group && (
          <button type="button" className="btn-acc" onClick={write} disabled={!email}>
            <Icon name="sent" size={16} />
            Написать
          </button>
        )}
        {!group && (
          <button type="button" className="btn-q" onClick={meet} disabled={!email}>
            <Icon name="cal" size={16} />
            Встреча
          </button>
        )}
        {!group && (
          <button type="button" className="btn-q" onClick={() => void copy()} disabled={!email}>
            <Icon name="doc" size={16} />
            Копировать адрес
          </button>
        )}
        {group && writable && (
          <button
            type="button"
            className="btn-q"
            onClick={() => {
              setGroupDraft(fullNameOf(card));
              setRenaming(true);
            }}
          >
            <Icon name="pen" size={16} />
            Переименовать
          </button>
        )}
        {writable && !group && (
          <div className="ct-groupwrap">
            <button type="button" className="btn-q" aria-expanded={groupMenu} onClick={() => setGroupMenu((v) => !v)}>
              В группу ▾
            </button>
            {groupMenu && (
              <div className="ct-menu ct-open" role="menu">
                {groups.length === 0 && <span className="ct-note">Групп пока нет</span>}
                {groups.map((g) => (
                  <button
                    key={String(g.id)}
                    type="button"
                    role="menuitem"
                    disabled={memberUidsOf(g).includes(String(card.uid))}
                    onClick={() => void addToGroup(String(g.id), fullNameOf(g))}
                  >
                    {fullNameOf(g)}
                    {memberUidsOf(g).includes(String(card.uid)) ? " ✓" : ""}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        {writable && !group && (
          <button type="button" className="btn-q" onClick={() => setEditing(true)}>
            <Icon name="pen" size={16} />
            Изменить
          </button>
        )}
        <span className="sp" />
        {writable && (
          confirmDelete ? (
            <>
              <span className="ct-note">Удалить {group ? "группу" : "контакт"}?</span>
              <button type="button" className="btn-q" onClick={() => setConfirmDelete(false)}>
                Нет
              </button>
              <button type="button" className="btn-q ct-danger" onClick={() => void destroy()} disabled={remove.isPending}>
                <Icon name="trash" size={16} />
                {remove.isPending ? "Удаляем…" : "Да, удалить"}
              </button>
            </>
          ) : (
            <button type="button" className="btn-q" onClick={() => setConfirmDelete(true)}>
              <Icon name="trash" size={16} />
              Удалить
            </button>
          )
        )}
      </div>
      <div className="main">
        <div className="ct-card card">
          <div className="ct-head">
            {photo ? (
              <img className="ct-photo" src={photo} alt="" />
            ) : (
              <span className="ava ct-ava ct-big">{initials(group ? name : fullNameOf(card), email)}</span>
            )}
            <div>
              <h1 className="ct-title">{name}</h1>
              <div className="ct-sub">
                {[title, org].filter(Boolean).join(" · ") || ""}
              </div>
              <div className="ct-book">
                {book ? `${book.name}${writable ? "" : " · справочник"}` : ""}
                {group ? " · группа рассылки" : ""}
              </div>
              {!writable && <div className="ct-note">Книга только для чтения — правка недоступна.</div>}
            </div>
          </div>
          <div className="fsep" />
          {group ? (
            <div className="ct-section">
              <div className="ct-cap">Участники ({memberUidsOf(card).length})</div>
              {members.map((m) => {
                const mEmail = primaryEmailOf(m);
                return (
                  <div key={String(m.uid)} className="ct-member">
                    <span className="ava ct-ava">{initials(fullNameOf(m), mEmail)}</span>
                    <button type="button" className="lk" onClick={() => navigate(`/contacts/${encodeURIComponent(String(m.id))}`)}>
                      {fullNameOf(m) || mEmail}
                    </button>
                    <span className="ct-sub">{mEmail}</span>
                    <span className="sp" />
                    {writable && (
                      <button
                        type="button"
                        className="x"
                        aria-label={`Убрать ${fullNameOf(m) || mEmail} из группы`}
                        onClick={() => void removeFromGroup(String(m.uid))}
                      >
                        <Icon name="x" size={14} />
                      </button>
                    )}
                  </div>
                );
              })}
              {missing.map((uid) => (
                <div key={uid} className="ct-member">
                  <span className="ava ct-ava">?</span>
                  <span className="ct-sub">{uid}</span>
                </div>
              ))}
              {memberUidsOf(card).length === 0 && <div className="ct-note">Участников пока нет — добавьте ниже.</div>}
              {writable && (
                <div className="ct-addmember">
                  <input
                    value={memberQuery}
                    onChange={(e) => setMemberQuery(e.target.value)}
                    placeholder="Найти участника по имени или адресу"
                    aria-label="Найти участника"
                  />
                  <div className="ct-candidates">
                    {candidates.map((c) => (
                      <button
                        key={String(c.id)}
                        type="button"
                        className="ct-member"
                        onClick={() => {
                          void addToGroup(String(card.id), fullNameOf(c));
                          setMemberQuery("");
                        }}
                      >
                        <span className="ava ct-ava">{initials(fullNameOf(c), primaryEmailOf(c))}</span>
                        {fullNameOf(c) || primaryEmailOf(c)}
                      </button>
                    ))}
                    {candidates.length === 0 && <span className="ct-note">Нет подходящих контактов.</span>}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <>
              {emails.length > 0 && (
                <div className="ct-section">
                  <div className="ct-cap">Адреса</div>
                  {emails.map((e) => (
                    <div key={e} className="ct-member">
                      <span className="ava ct-ava">@</span>
                      <span className="ct-name">{e}</span>
                      <span className="sp" />
                      <button
                        type="button"
                        className="lk"
                        onClick={() => {
                          navigate(`/compose?to=${encodeURIComponent(fullNameOf(card) ? `${fullNameOf(card)} <${e}>` : e)}`);
                        }}
                      >
                        Написать
                      </button>
                    </div>
                  ))}
                </div>
              )}
              {phones.length > 0 && (
                <div className="ct-section">
                  <div className="ct-cap">Телефоны</div>
                  {phones.map((p) => (
                    <div key={p} className="ct-member">
                      <span className="ava ct-ava">☎</span>
                      <span className="ct-name">{p}</span>
                    </div>
                  ))}
                </div>
              )}
              {notes && (
                <div className="ct-section">
                  <div className="ct-cap">Заметки</div>
                  <div className="ct-notes">{notes}</div>
                </div>
              )}
            </>
          )}
          {updated && <div className="ct-note">Изменена: {new Date(updated).toLocaleString("ru")}</div>}
        </div>
      </div>
      {editing && (
        <CardEditor
          title="Изменить контакт"
          initial={formOf(card)}
          saving={update.isPending}
          onClose={closeEditor}
          onSave={(form) => void saveForm(form)}
        />
      )}
      {renaming && (
        <aside className="cal-panel" aria-label="Переименовать группу">
          <div className="cal-panel-head">
            <b>Переименовать группу</b>
            <button type="button" className="cal-x" aria-label="Закрыть форму" onClick={() => setRenaming(false)}>
              <Icon name="x" size={16} />
            </button>
          </div>
          <div className="cal-panel-body">
            <label className="cal-field">
              <span>Имя группы</span>
              <input value={groupDraft} onChange={(e) => setGroupDraft(e.target.value)} autoFocus />
            </label>
          </div>
          <div className="cal-panel-foot">
            <span className="sp" />
            <button type="button" className="button" onClick={() => setRenaming(false)}>
              Отмена
            </button>
            <button
              type="button"
              className="button button-primary"
              disabled={renameGroup.isPending || !groupDraft.trim()}
              onClick={() => void submitRename()}
            >
              Сохранить
            </button>
          </div>
        </aside>
      )}
    </section>
  );
}
