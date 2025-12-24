
export type TruncateTextOptions = {
  text: string;
  maxLength?: number;
  suffix?: string;
};

export function truncateText({
  text,
  maxLength = 10,
  suffix = '...',
}: TruncateTextOptions): string {
  return text.length > maxLength
    ? text.substring(0, maxLength) + suffix
    : text;
}
