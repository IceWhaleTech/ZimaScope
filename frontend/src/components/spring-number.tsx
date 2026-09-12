/**
 * Animated numeric readout. Values retarget through a critically damped
 * spring (no overshoot) starting from the live on-screen value, so live rate
 * updates ease instead of snapping — Apple's fluid-number behavior.
 */

import { useEffect } from "react";
import { motion, useSpring, useTransform } from "motion/react";

export function SpringNumber({
  value,
  format,
  className,
}: {
  value: number;
  format: (value: number) => string;
  className?: string;
}) {
  const spring = useSpring(value, { stiffness: 140, damping: 26 });
  useEffect(() => {
    spring.set(value);
  }, [spring, value]);
  const text = useTransform(spring, (latest) => format(latest));
  return <motion.span className={className}>{text}</motion.span>;
}
