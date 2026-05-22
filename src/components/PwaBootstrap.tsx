'use client';

import { useEffect } from 'react';

export default function PwaBootstrap() {
  useEffect(() => {
    if (!('serviceWorker' in navigator) || process.env.NODE_ENV !== 'production') return;

    navigator.serviceWorker.register('/sw.js').catch(() => {
      // PWA support is progressive; the dashboard still works without a worker.
    });
  }, []);

  return null;
}
