//! Шрифт консоли Linux (TUI-12, решение 119): прочитать шрифт и карту Unicode, подменить четыре глифа и
//! вернуть всё при выходе — как в Norton Commander 5. Нужен плавному курсору мыши текстового интерфейса
//! (уровень 3): глифы перерисовываются под стрелку со сдвигом внутри ячейки, а ячейки курсора печатают
//! коды области частного использования Юникода (PUA), добавленные в карту.
//!
//! Вызовы `ioctl` завершаются сразу, но открытие ([`ConsoleFont::open`]) делает несколько запросов —
//! из async его звать в `spawn_blocking`; запись шрифта требует `CAP_SYS_TTY_CONFIG` (обычно root на
//! консоли узла) и vt-консоль, отказ — причина уйти вызывающему коду на уровень 4 (подсветка ячейки).
//! `unsafe` — только внутри `tp-sys`: аргументы ioctl содержат сырые указатели.
//!
//! Формат данных шрифта («расширенный», как у `setfont` из kbd): глиф — 32 строки по `ceil(ширина/8)` байт,
//! используются первые `высота` строк; [`ConsoleFont::set_glyphs`] принимает глифы свёрнуто — `высота`
//! строк подряд, по `ceil(ширина/8)` байт на строку, старший бит — левый пиксель.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use nix::libc::{c_int, c_uint, c_ulong, c_ushort, ioctl};

/// `KDFONTOP` — шрифт консоли (`linux/kd.h`).
const KDFONTOP: c_ulong = 0x4B72;
/// `GIO_UNIMAP` — чтение карты Unicode.
const GIO_UNIMAP: c_ulong = 0x4B67;
/// `PIO_UNIMAP` — запись карты Unicode (заменяет всю карту).
const PIO_UNIMAP: c_ulong = 0x4B66;
/// Операция `KD_FONT_OP_SET`.
const OP_SET: c_uint = 0;
/// Операция `KD_FONT_OP_GET`.
const OP_GET: c_uint = 1;

/// Строк растра на глиф в расширенном формате шрифта.
pub const GLYPH_ROWS: usize = 32;
/// Сколько глифов подменяем (блок 2×2).
pub const CURSOR_GLYPHS: usize = 4;
/// Наибольшая карта Unicode, которую принимает ядро (`E_TABSZ`).
const MAX_UNIMAP: usize = 4096;
/// Начало диапазона PUA под коды курсора.
const PUA: u16 = 0xF500;

/// Аргумент `KDFONTOP` (`struct console_font_op`).
#[repr(C)]
struct FontOp {
    op: c_uint,
    flags: c_uint,
    width: c_uint,
    height: c_uint,
    charcount: c_uint,
    data: *mut u8,
}

/// Пара «код Unicode — позиция в шрифте» (`struct unipair`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unipair {
    /// Код Unicode.
    pub unicode: u16,
    /// Позиция глифа в шрифте.
    pub fontpos: u16,
}

/// Аргумент `GIO_UNIMAP`/`PIO_UNIMAP` (`struct unimapdesc`).
#[repr(C)]
struct Unimapdesc {
    entry_ct: c_ushort,
    entries: *mut Unipair,
}

#[allow(unsafe_code)]
fn font_op(fd: c_int, op: &mut FontOp) -> io::Result<()> {
    let r = unsafe { ioctl(fd, KDFONTOP, op as *mut FontOp) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn unimap(fd: c_int, req: c_ulong, map: &mut Unimapdesc) -> io::Result<()> {
    let r = unsafe { ioctl(fd, req, map as *mut Unimapdesc) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Прочитать карту Unicode консоли; при тесном буфере ядро называет нужный размер.
fn read_unimap(fd: c_int) -> io::Result<Vec<Unipair>> {
    let mut cap = 512usize;
    loop {
        let mut entries = vec![
            Unipair {
                unicode: 0,
                fontpos: 0,
            };
            cap
        ];
        let mut desc = Unimapdesc {
            entry_ct: cap as c_ushort,
            entries: entries.as_mut_ptr(),
        };
        match unimap(fd, GIO_UNIMAP, &mut desc) {
            Ok(()) => {
                entries.truncate(usize::from(desc.entry_ct));
                return Ok(entries);
            }
            // EAGAIN/ENOSPC — мало места, ядро называет нужный размер.
            Err(e) if matches!(e.raw_os_error(), Some(code) if code == nix::libc::EAGAIN || code == nix::libc::ENOSPC) =>
            {
                let need = usize::from(desc.entry_ct).max(cap * 2);
                if cap >= MAX_UNIMAP || need > MAX_UNIMAP {
                    return Err(e);
                }
                cap = need;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Выбрать позиции глифов: свободные (без кодов в карте), с конца; не хватает — последние четыре.
fn pick_slots(charcount: u16, map: &[Unipair]) -> [u16; CURSOR_GLYPHS] {
    let mut slots = [0u16; CURSOR_GLYPHS];
    let mut n = 0;
    for p in (0..charcount)
        .rev()
        .filter(|p| !map.iter().any(|e| e.fontpos == *p))
    {
        if n == CURSOR_GLYPHS {
            break;
        }
        slots[n] = p;
        n += 1;
    }
    // Не хватает свободных — последние четыре: их глифы перезапишутся, но коды при них сохранятся.
    if n < CURSOR_GLYPHS {
        for (i, s) in slots.iter_mut().enumerate() {
            *s = charcount - 1 - i as u16;
        }
    }
    slots
}

/// Выбрать коды PUA, которых нет в карте.
fn pick_codes(map: &[Unipair]) -> [u16; CURSOR_GLYPHS] {
    let mut codes = [0u16; CURSOR_GLYPHS];
    let mut next = PUA;
    for c in &mut codes {
        while map.iter().any(|e| e.unicode == next) {
            next += 1;
        }
        *c = next;
        next += 1;
    }
    codes
}

/// Записать глифы в расширенный буфер шрифта: каждый — 32 строки по `bytewidth` байт, хвост — нули.
fn pack(font: &mut [u8], bytewidth: usize, slots: &[u16; CURSOR_GLYPHS], glyphs: &[Vec<u8>]) {
    for (i, bmp) in glyphs.iter().take(CURSOR_GLYPHS).enumerate() {
        let height = bmp.len() / bytewidth.max(1);
        let at = usize::from(slots[i]) * GLYPH_ROWS * bytewidth;
        for row in 0..GLYPH_ROWS {
            for b in 0..bytewidth {
                let src = (row < height).then_some(row * bytewidth + b);
                if let Some(dst) = font.get_mut(at + row * bytewidth + b) {
                    *dst = src.map_or(0, |s| bmp.get(s).copied().unwrap_or(0));
                }
            }
        }
    }
}

/// Поставить шрифт и карту Unicode на дескриптор консоли.
fn set_font_map(
    fd: c_int,
    width: u16,
    height: u16,
    charcount: u16,
    font: &[u8],
    map: &[Unipair],
) -> io::Result<()> {
    let mut font = font.to_vec();
    let mut op = FontOp {
        op: OP_SET,
        flags: 0,
        width: u32::from(width),
        height: u32::from(height),
        charcount: u32::from(charcount),
        data: font.as_mut_ptr(),
    };
    font_op(fd, &mut op)?;
    let mut entries = map.to_vec();
    let mut desc = Unimapdesc {
        entry_ct: entries.len() as c_ushort,
        entries: entries.as_mut_ptr(),
    };
    unimap(fd, PIO_UNIMAP, &mut desc)
}

/// Шрифт консоли с подменой четырёх глифов: при выходе шрифт и карта возвращаются как были (RAII).
#[derive(Debug)]
pub struct ConsoleFont {
    fd: std::fs::File,
    width: u16,
    height: u16,
    charcount: u16,
    /// Рабочий шрифт (расширенный формат) — исходный с нашими глифами.
    font: Vec<u8>,
    /// Исходный шрифт для возврата.
    saved_font: Vec<u8>,
    /// Рабочая карта Unicode — исходная с нашими парами.
    map: Vec<Unipair>,
    /// Исходная карта для возврата.
    saved_map: Vec<Unipair>,
    /// Позиции подменённых глифов.
    slots: [u16; CURSOR_GLYPHS],
    /// Коды PUA подменённых глифов.
    codes: [u16; CURSOR_GLYPHS],
}

impl ConsoleFont {
    /// Прочитать шрифт и карту Unicode консоли и занять четыре глифа под коды PUA.
    /// Отказ (`ENOSYS`, `ENOTTY`, `EPERM`, нет `/dev/tty`) — причина перейти на уровень 4 вызывающему коду.
    pub fn open() -> io::Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC)
            .open("/dev/tty")?;
        let raw = fd.as_raw_fd();
        // Сначала метаданные (data = NULL): ядро называет ширину, высоту и число глифов.
        let mut op = FontOp {
            op: OP_GET,
            flags: 0,
            width: 32,
            height: 32,
            charcount: 512,
            data: std::ptr::null_mut(),
        };
        font_op(raw, &mut op)?;
        let (width, height, charcount) = (op.width as u16, op.height as u16, op.charcount as u16);
        if width == 0
            || height == 0
            || charcount < CURSOR_GLYPHS as u16
            || width > 32
            || height > GLYPH_ROWS as u16
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("шрифт консоли {width}×{height}×{charcount} не подходит"),
            ));
        }
        let bytewidth = usize::from(width.div_ceil(8));
        let mut font = vec![0u8; usize::from(charcount) * GLYPH_ROWS * bytewidth];
        op.width = u32::from(width);
        op.height = GLYPH_ROWS as c_uint;
        op.charcount = u32::from(charcount);
        op.data = font.as_mut_ptr();
        font_op(raw, &mut op)?;
        // Карту, которую не удалось прочесть, нельзя вернуть — не трогаем консоль вовсе.
        let saved_map = read_unimap(raw)?;
        let slots = pick_slots(charcount, &saved_map);
        let codes = pick_codes(&saved_map);
        let mut map = saved_map.clone();
        map.extend(
            codes
                .iter()
                .zip(slots)
                .map(|(&unicode, fontpos)| Unipair { unicode, fontpos }),
        );
        set_font_map(raw, width, height, charcount, &font, &map)?;
        let saved_font = font.clone();
        Ok(Self {
            fd,
            width,
            height,
            charcount,
            font,
            saved_font,
            map,
            saved_map,
            slots,
            codes,
        })
    }

    /// Размер ячейки в пикселях — размер глифа шрифта.
    pub fn cell(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// Коды PUA подменённых глифов: их печатают ячейки курсора.
    pub fn codes(&self) -> [u16; CURSOR_GLYPHS] {
        self.codes
    }

    /// Байтов на строку растра.
    fn bytewidth(&self) -> usize {
        usize::from(self.width.div_ceil(8))
    }

    /// Перерисовать четыре глифа: каждый — `height` строк по `bytewidth` байт; исходный шрифт и карта
    /// для возврата не меняются.
    pub fn set_glyphs(&mut self, glyphs: &[Vec<u8>; CURSOR_GLYPHS]) -> io::Result<()> {
        self.apply_glyphs(glyphs)?;
        self.push()
    }

    /// Вписать глифы в рабочий шрифт (без ioctl); `set_glyphs` гонит результат в консоль.
    fn apply_glyphs(&mut self, glyphs: &[Vec<u8>; CURSOR_GLYPHS]) -> io::Result<()> {
        let bytewidth = self.bytewidth();
        let want = usize::from(self.height) * bytewidth;
        if glyphs.iter().any(|g| g.len() != want) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("глиф — {want} байт"),
            ));
        }
        let slots = self.slots;
        pack(&mut self.font, bytewidth, &slots, glyphs);
        Ok(())
    }

    /// Записать рабочий шрифт и карту в консоль.
    fn push(&mut self) -> io::Result<()> {
        set_font_map(
            self.fd.as_raw_fd(),
            self.width,
            self.height,
            self.charcount,
            &self.font,
            &self.map,
        )
    }

    /// Вернуть шрифт и карту как было; ошибки — только в журнал.
    fn restore(&mut self) {
        if let Err(e) = set_font_map(
            self.fd.as_raw_fd(),
            self.width,
            self.height,
            self.charcount,
            &self.saved_font,
            &self.saved_map,
        ) {
            tracing::warn!("возврат шрифта консоли: {e}");
        }
    }
}

impl Drop for ConsoleFont {
    fn drop(&mut self) {
        self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(u: u16, f: u16) -> Unipair {
        Unipair {
            unicode: u,
            fontpos: f,
        }
    }

    /// Свободные позиции выбираем с конца, коды PUA — пропуская занятые.
    #[test]
    fn picks() {
        let map = vec![pair(0x41, 1), pair(0xF501, 5), pair(0xF502, 6)];
        assert_eq!(pick_slots(10, &map), [9, 8, 7, 4]);
        assert_eq!(pick_slots(4, &map), [3, 2, 1, 0]);
        assert_eq!(pick_codes(&map), [0xF500, 0xF503, 0xF504, 0xF505]);
        assert!(
            pick_codes(&map)
                .iter()
                .all(|c| map.iter().all(|e| e.unicode != *c))
        );
    }

    /// Упаковка: глиф ложится в свои 32 строки, ниже роста — нули, чужие глифы не тронуты.
    #[test]
    fn packing() {
        let mut font = vec![7u8; 5 * GLYPH_ROWS];
        let bmp = [
            vec![0xAA, 0x55, 0x0F],
            vec![1, 2, 3],
            Vec::new(),
            vec![9, 9, 9],
        ];
        pack(&mut font, 1, &[4, 3, 2, 1], &bmp);
        assert_eq!(
            &font[4 * GLYPH_ROWS..4 * GLYPH_ROWS + 3],
            &[0xAA, 0x55, 0x0F]
        );
        assert_eq!(&font[4 * GLYPH_ROWS + 3..5 * GLYPH_ROWS], &[0; 29]);
        assert_eq!(&font[3 * GLYPH_ROWS..3 * GLYPH_ROWS + 3], &[1, 2, 3]);
        assert_eq!(
            &font[2 * GLYPH_ROWS..3 * GLYPH_ROWS],
            &[0; GLYPH_ROWS],
            "пустой глиф — нули"
        );
        assert_eq!(&font[GLYPH_ROWS..GLYPH_ROWS + 3], &[9, 9, 9]);
        assert_eq!(&font[0..GLYPH_ROWS], &[7; GLYPH_ROWS], "чужой глиф цел");
        // Широкий шрифт: по 2 байта на строку в каждых 32 строках.
        let mut wide = vec![0u8; 4 * GLYPH_ROWS * 2];
        pack(
            &mut wide,
            2,
            &[3, 2, 1, 0],
            &[
                vec![1, 2, 3, 4],
                vec![5, 6, 7, 8],
                Vec::new(),
                vec![9, 10, 11, 12],
            ],
        );
        assert_eq!(
            &wide[3 * GLYPH_ROWS * 2..3 * GLYPH_ROWS * 2 + 4],
            &[1, 2, 3, 4]
        );
        assert_eq!(
            &wide[2 * GLYPH_ROWS * 2..2 * GLYPH_ROWS * 2 + 4],
            &[5, 6, 7, 8]
        );
        assert_eq!(&wide[GLYPH_ROWS * 2..GLYPH_ROWS * 2 + 4], &[0; 4]);
        assert_eq!(&wide[0..4], &[9, 10, 11, 12]);
        assert_eq!(&wide[4..GLYPH_ROWS * 2], &[0; 60]);
    }

    /// Макет без ioctl: перерисовка меняет рабочий шрифт, а исходные байты и карта для возврата — нет.
    #[test]
    fn redraw_keeps_originals_for_restore() {
        let saved_map = vec![pair(0x41, 1)];
        let mut c = ConsoleFont {
            fd: std::fs::File::open("/dev/null").expect("/dev/null"),
            width: 8,
            height: 16,
            charcount: 8,
            font: vec![1u8; 8 * GLYPH_ROWS],
            saved_font: vec![1u8; 8 * GLYPH_ROWS],
            map: saved_map.clone(),
            saved_map: saved_map.clone(),
            slots: [7, 6, 5, 4],
            codes: [0xF500, 0xF501, 0xF502, 0xF503],
        };
        let want = core::array::from_fn(|_| vec![0xAAu8; 16]);
        c.apply_glyphs(&want).expect("перерисовка");
        assert_eq!(
            c.saved_font,
            vec![1u8; 8 * GLYPH_ROWS],
            "исходные байты целы"
        );
        assert_eq!(c.saved_map, saved_map, "исходная карта цела");
        assert_eq!(c.map, saved_map, "перерисовка карту не трогает");
        for slot in c.slots {
            let at = usize::from(slot) * GLYPH_ROWS;
            assert_eq!(&c.font[at..at + 16], &[0xAA; 16], "слот {slot}");
        }
        // Чужой размер глифа — отказ без изменений.
        let bad = [vec![0u8; 3], vec![0; 16], vec![0; 16], vec![0; 16]];
        assert!(c.apply_glyphs(&bad).is_err());
    }
}
