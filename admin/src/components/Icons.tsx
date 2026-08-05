import type { SVGProps } from "react";

function Icon({ children, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {...props}>
      {children}
    </svg>
  );
}
export function GridIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </Icon>
  );
}
export function DocumentIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <path d="M6 2.75h8.8L19 7v14.25H6z" />
      <path d="M14.5 2.9V7h4.1M9 11h7M9 15h7M9 18h5" />
    </Icon>
  );
}
export function PulseIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <path d="M2 13h4l2.2-7 3.2 12 2.3-8 1.7 5H22" />
    </Icon>
  );
}
export function KeyIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <circle cx="8" cy="14" r="4" />
      <path d="m11 11 8-8 2 2-2 2 1.5 1.5-2 2L17 9l-3 3" />
    </Icon>
  );
}
export function ShieldIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <path d="M12 2.7 20 6v5.7c0 4.9-3.3 8.2-8 9.7-4.7-1.5-8-4.8-8-9.7V6z" />
      <path d="m8.2 12.2 2.4 2.4 5.3-5.3" />
    </Icon>
  );
}
export function MenuIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Icon>
  );
}
export function CloseIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <Icon {...props}>
      <path d="m6 6 12 12M18 6 6 18" />
    </Icon>
  );
}
