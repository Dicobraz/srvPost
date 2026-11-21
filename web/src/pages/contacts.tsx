/*
  Раздел «Контакты» (WEB-07): книги слева — личные (правка) и «Организация» (GAL, read-only,
  признак — myRights.mayWrite=false из AddressBook/get), группы рассылки; список с поиском по
  имени/адресу/организации (серверный text-фильтр ContactCard/query, устойчивость к раскладке —
  второй вариант qwerty→йцукен через OR). Карточка — отдельной вкладкой приложения
  (/contacts/:id, DESIGN.md: контакты — таб, не модалка). Контекстное меню строки (PARITY
  contacts.*): Написать (композер с получателем), Встреча (форма календаря с участником),
  Копировать адрес (буфер + тост), Открыть/Изменить (карточка, форма), Удалить, В группу.
  Формы — панели inline (не модалки), как в макетах.
*/
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";

import { Icon } from "../mail/icons";
import { useJmap } from "../mail/context";
import { useToast } from "../mail/toast";
import { loadTranslit } from "../mail/settings";
import {
  hasContactsCapability,
  useAddressBooks,
  useContactCreate,
  useContactDelete,
  useContactSearch,
  useContactSnapshot,
  useGroupCreate,
  useGroupMemberMutation,
} from "../contacts/queries";
import {
  bookIdOf,
  bookWritable,
  fullNameOf,
  initials,
  isGroupCard,
  memberUidsOf,
  organizationOf,
  primaryEmailOf,
  phonesOf,
  type ContactCard,
} from "../contacts/model";
import { CardEditor, emptyForm } from "../contacts/CardEditor";
import { copyText } from "../contacts/clipboard";

/** Поисковая пауза: один серверный запрос на остановку набора. */
const SEARCH_DEBOUNCE_MS = 250;

/** Поиск активен после паузы набора. */
function useDebounced(value: string): string {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [value]);
  return debounced;
}

export function ContactsPage() {
  const env = useJmap();
  const toast = useToast();
  const navigate = useNavigate();

  const translit = useMemo(() => loadTranslit(), []);
  const [query, setQuery] = useState("");
  const debounced = useDebounced(query);
  const [bookId, setBookId] = useState<string | null>(null);
  const [creating, setCreating] = useState<null | "contact" | "group">(null);
  const [groupName, setGroupName] = useState("");
  const [menuFor, setMenuFor] = useState<string | null>(null);

  const books = useAddressBooks();
  const snapshot = useContactSnapshot();
  const found = useContactSearch({ query: debounced, translit });

  const create = useContactCreate();
  const createGroup = useGroupCreate();
  const remove = useContactDelete();
  const member = useGroupMemberMutation();

  // Книга для новой карточки: выбранная (если писать можно), иначе книга по умолчанию.
  const defaultBook =
    books.find((b) => bookId === b.id && bookWritable(b)) ??
    books.find((b) => b.isDefault && bookWritable(b)) ??
    books.find((b) => bookWritable(b)) ??
    null;

  // Список: с запросом — серверный поиск (текст OR вариантов раскладки); без — снимок с
  // фильтром книги. Группы (kind=group) живут в сайдбаре и открываются карточкой группы.
  const cards = useMemo(() => {
    const source = debounced.trim() ? found : snapshot;
    if (!source) return [];
    return source.filter((c) => !isGroupCard(c)).filter((c) => !bookId || bookIdOf(c) === bookId);
  }, [debounced, found, snapshot, bookId]);

  const groups = useMemo(() => snapshot.filter(isGroupCard), [snapshot]);
  const bookById = useMemo(() => new Map(books.map((b) => [b.id, b])), [books]);

  // «В группу»: карточки доступны, если книгу группы можно писать (свои книги).
  const addableGroups = useMemo(
    () => groups.filter((g) => bookWritable(bookById.get(bookIdOf(g) ?? "") ?? null)),
    [groups, bookById],
  );
  const uidsByGroup = useMemo(
    () => new Map(groups.map((g) => [String(g.id), new Set(memberUidsOf(g))])),
    [groups],
  );

  const openCard = (card: ContactCard) => {
    setMenuFor(null);
    navigate(`/contacts/${encodeURIComponent(String(card.id))}`);
  };

  const writeTo = (card: ContactCard) => {
    setMenuFor(null);
    const email = primaryEmailOf(card);
    if (!email) {
      toast.show("У контакта нет адреса — добавьте его в карточке.");
      return;
    }
    const name = fullNameOf(card);
    const to = name ? `${name} <${email}>` : email;
    navigate(`/compose?to=${encodeURIComponent(to)}`);
  };

  const meetWith = (card: ContactCard) => {
    setMenuFor(null);
    const email = primaryEmailOf(card);
    if (!email) {
      toast.show("У контакта нет адреса для приглашения.");
      return;
    }
    const name = fullNameOf(card);
    navigate(
      `/calendar?attendee=${encodeURIComponent(email)}${
        name ? `&attendeeName=${encodeURIComponent(name)}` : ""
      }`,
    );
  };

  const copyAddress = async (card: ContactCard) => {
    setMenuFor(null);
    const email = primaryEmailOf(card);
    if (!email) {
      toast.show("У контакта нет адреса.");
      return;
    }
    toast.show((await copyText(email)) ? `Адрес скопирован: ${email}` : "Не удалось скопировать адрес.");
  };

  const deleteCard = async (card: ContactCard) => {
    setMenuFor(null);
    try {
      await remove.mutateAsync(String(card.id));
      toast.show(`Контакт удалён: ${fullNameOf(card) || primaryEmailOf(card)}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не удалил контакт.");
    }
  };

  const addToGroup = async (card: ContactCard, group: ContactCard) => {
    setMenuFor(null);
    try {
      await member.mutateAsync({ groupId: String(group.id), uid: String(card.uid), add: true });
      toast.show(`Добавлено в группу: ${fullNameOf(group) || ""}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не обновил группу.");
    }
  };

  const submitCreate = async (form: Parameters<typeof create.mutateAsync>[0]["form"]) => {
    if (!defaultBook) {
      toast.show("Нет личной книги — создать контакт нельзя.");
      return;
    }
    try {
      const id = await create.mutateAsync({ form, bookId: defaultBook.id });
      setCreating(null);
      toast.show("Контакт создан");
      navigate(`/contacts/${encodeURIComponent(id)}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не сохранил контакт.");
    }
  };

  const submitGroup = async () => {
    const name = groupName.trim();
    if (!name) {
      toast.show("У группы должно быть имя.");
      return;
    }
    if (!defaultBook) {
      toast.show("Нет личной книги — создать группу нельзя.");
      return;
    }
    try {
      const id = await createGroup.mutateAsync({ name, bookId: defaultBook.id });
      setCreating(null);
      setGroupName("");
      toast.show(`Группа создана: ${name}`);
      navigate(`/contacts/${encodeURIComponent(id)}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Сервер не создал группу.");
    }
  };

  if (!hasContactsCapability(env)) {
    return (
      <section className="stub">
        <h1>Контакты</h1>
        <p>На этом узле нет адресных книг (капабилити contacts не объявлена).</p>
      </section>
    );
  }

  const individuals = snapshot.filter((c) => !isGroupCard(c));

  return (
    <section className="mail contacts" aria-label="Контакты">
      <div className="cmd">
        <button
          type="button"
          className="btn-acc"
          onClick={() => {
            setCreating("contact");
            setMenuFor(null);
          }}
          disabled={!defaultBook}
          title={defaultBook ? "Новый контакт" : "Нет личной книги — правка недоступна"}
        >
          <Icon name="person" size={16} />
          Новый контакт
        </button>
        <button
          type="button"
          className="btn-q"
          onClick={() => {
            setCreating("group");
            setMenuFor(null);
          }}
          disabled={!defaultBook}
        >
          <Icon name="folder" size={16} />
          Новая группа
        </button>
        <div className="searchbar" role="search">
          <Icon name="search" size={16} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Поиск: имя, адрес, организация (раскладка не важна)"
            aria-label="Поиск контактов"
          />
          {query && (
            <button type="button" className="clr" aria-label="Очистить поиск" onClick={() => setQuery("")}>
              <Icon name="x" size={14} />
            </button>
          )}
        </div>
        <span className="sp" />
      </div>
      <div className="main">
        <aside className="tree" aria-label="Книги и группы">
          <div className="ct-cap">Книги</div>
          <button type="button" className={`fold${bookId === null ? " on" : ""}`} onClick={() => setBookId(null)}>
            <span className="name">Все контакты</span>
            <span className="n">{individuals.length}</span>
          </button>
          {books.map((b) => (
            <button
              key={b.id}
              type="button"
              className={`fold${bookId === b.id ? " on" : ""}`}
              onClick={() => setBookId(b.id)}
              title={bookWritable(b) ? b.name : `${b.name} — только для чтения`}
            >
              <span className="name">{b.name}</span>
              {!bookWritable(b) && <span className="ct-ro">справочник</span>}
              <span className="n">{individuals.filter((c) => bookIdOf(c) === b.id).length}</span>
            </button>
          ))}
          <div className="ct-cap">Группы</div>
          {groups.map((g) => (
            <button key={String(g.id)} type="button" className="fold" onClick={() => openCard(g)} title="Группа рассылки">
              <span className="name">{fullNameOf(g) || "(без имени)"}</span>
              <span className="n">{memberUidsOf(g).length}</span>
            </button>
          ))}
          {groups.length === 0 && <div className="ct-note">Групп пока нет</div>}
        </aside>
        <div className="list" aria-label="Список контактов">
          <div className="lhead">
            <span className="sec">{debounced.trim() ? `Поиск: ${debounced.trim()}` : "Контакты"}</span>
            <span className="sort">{cards.length} из {individuals.length}</span>
          </div>
          <div className="rows">
            {cards.map((card) => {
              const email = primaryEmailOf(card);
              const book = bookById.get(bookIdOf(card) ?? "") ?? null;
              const writable = book ? bookWritable(book) : false;
              const label = fullNameOf(card) || email || "(без имени)";
              return (
                <div
                  key={String(card.id)}
                  className="msg ct-line-card"
                  onClick={() => openCard(card)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") openCard(card);
                  }}
                >
                  <span className="ava ct-ava">{initials(fullNameOf(card), email)}</span>
                  <span className="ct-line">
                    <span className="ct-name">{label}</span>
                    <span className="ct-sub">
                      {[organizationOf(card), email ?? phonesOf(card)[0] ?? ""].filter(Boolean).join(" · ")}
                    </span>
                  </span>
                  <span className="ct-book">
                    {book ? `${book.name}${bookWritable(book) ? "" : " · справочник"}` : ""}
                  </span>
                  <button
                    type="button"
                    className="ct-menu-btn"
                    aria-label={`Меню контакта ${label}`}
                    aria-expanded={menuFor === String(card.id)}
                    onClick={(e) => {
                      e.stopPropagation();
                      setMenuFor(menuFor === String(card.id) ? null : String(card.id));
                    }}
                  >
                    ⋯
                  </button>
                  {menuFor === String(card.id) && (
                    <div className="ct-menu" role="menu" onClick={(e) => e.stopPropagation()}>
                      <button type="button" role="menuitem" onClick={() => writeTo(card)}>
                        Написать
                      </button>
                      <button type="button" role="menuitem" onClick={() => meetWith(card)}>
                        Встреча
                      </button>
                      <button type="button" role="menuitem" onClick={() => void copyAddress(card)}>
                        Копировать адрес
                      </button>
                      <button type="button" role="menuitem" onClick={() => openCard(card)}>
                        Открыть карточку
                      </button>
                      {writable && (
                        <button
                          type="button"
                          role="menuitem"
                          onClick={() => {
                            setMenuFor(null);
                            navigate(`/contacts/${encodeURIComponent(String(card.id))}?edit=1`);
                          }}
                        >
                          Изменить
                        </button>
                      )}
                      {writable &&
                        addableGroups.map((g) => {
                          const added = uidsByGroup.get(String(g.id))?.has(String(card.uid)) ?? false;
                          return (
                            <button
                              key={String(g.id)}
                              type="button"
                              role="menuitem"
                              disabled={added}
                              title={added ? "Уже в группе — убрать можно в карточке группы" : undefined}
                              onClick={() => void addToGroup(card, g)}
                            >
                              В группу: {fullNameOf(g)}{added ? " ✓" : ""}
                            </button>
                          );
                        })}
                      {writable && (
                        <button type="button" role="menuitem" className="ct-danger" onClick={() => void deleteCard(card)}>
                          Удалить
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            {cards.length === 0 && (
              <div className="ct-empty">
                {debounced.trim()
                  ? "Ничего не найдено — проверьте запрос или раскладку."
                  : bookId
                    ? "В этой книге пока нет контактов."
                    : "Контактов пока нет — создайте первый."}
              </div>
            )}
          </div>
        </div>
        {creating === "contact" && (
          <CardEditor
            title="Новый контакт"
            initial={emptyForm()}
            saving={create.isPending}
            onClose={() => setCreating(null)}
            onSave={(form) => void submitCreate(form)}
          />
        )}
        {creating === "group" && (
          <aside className="cal-panel" aria-label="Новая группа">
            <div className="cal-panel-head">
              <b>Новая группа</b>
              <button type="button" className="cal-x" aria-label="Закрыть форму" onClick={() => setCreating(null)}>
                <Icon name="x" size={16} />
              </button>
            </div>
            <div className="cal-panel-body">
              <label className="cal-field">
                <span>Имя группы</span>
                <input
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  placeholder="Например: Команда почты"
                  autoFocus
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void submitGroup();
                  }}
                />
              </label>
              <p className="cal-note">
                Участники добавляются из карточек контактов; группа — карточка рассылки (RFC 9610).
              </p>
            </div>
            <div className="cal-panel-foot">
              <span className="sp" />
              <button type="button" className="button" onClick={() => setCreating(null)}>
                Отмена
              </button>
              <button
                type="button"
                className="button button-primary"
                disabled={createGroup.isPending}
                onClick={() => void submitGroup()}
              >
                {createGroup.isPending ? "Создаём…" : "Создать"}
              </button>
            </div>
          </aside>
        )}
      </div>
    </section>
  );
}
