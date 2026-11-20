// Раздел «Почта» (WEB-01): заглушка оболочки. Ящики, список и чтение писем — WEB-03 (JMAP Mail),
// композер — WEB-04; данные пойдут через JMAP того же узла (same-origin, ADR 2026-11-20).
export function MailPage() {
  return (
    <section className="stub">
      <h1>Почта</h1>
      <p>Раздел в разработке.</p>
    </section>
  );
}
