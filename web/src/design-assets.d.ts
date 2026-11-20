// Виртуальные модули `design/<файл>` (vite.config.ts, UI-19): содержимое файла из ../design строкой.
declare module "design/*" {
  const content: string;
  export default content;
}
