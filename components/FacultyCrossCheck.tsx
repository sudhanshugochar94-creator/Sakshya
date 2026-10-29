'use client';
import React from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';
import { Btn, Card, Empty, ErrorBox, Loading, useLoad } from '@/components/ui';

const Side = ({ p }: { p: any }) => (
  <div className="min-w-0 text-xs"><div className="font-semibold">{p.name}</div>
    <div className="text-slate-600">{p.institution} · <Link className="text-indigo-700 underline" href={`/applications/${p.application_id}`}>{p.application_id}</Link></div>
    <div className="font-mono text-[10px] text-slate-500">{p.file}{p.uan ? ` · UAN ${p.uan}` : ''}{p.pan ? ` · PAN ${p.pan}` : ''}</div></div>
);

/** Finds the same person listed as faculty by more than one institution. Text only: no biometrics. */
export default function FacultyCrossCheck() {
  const { data, error, loading, reload } = useLoad<any>(() => api('/lab/faculty-cross-check'));
  return (
    <Card title="Faculty cross-check across institutions" right={<Btn variant="ghost" onClick={reload}>Re-scan</Btn>}>
      {loading && <Loading />}{error != null && <ErrorBox error={error} />}
      {data && (<>
        <p className="mb-2 text-xs text-slate-600">Scanned {data.rosters} faculty list(s), {data.people} named people. <b>Strong</b> = same UAN or PAN; <b>weak</b> = same or near-identical name with no identifier to confirm.</p>
        {data.pairs.length === 0 ? <Empty>No person appears in more than one institution&apos;s faculty list.</Empty> : (
          <ul className="space-y-2">{data.pairs.map((p: any, i: number) => (
            <li key={i} className="rounded-lg border border-slate-200 p-2.5 dark:border-slate-700">
              <div className="mb-1.5 flex items-center gap-2 text-xs"><span className={`rounded px-1.5 py-0.5 font-bold uppercase ${p.level === 'strong' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'}`}>{p.level}</span><span>{p.reason}</span></div>
              <div className="grid grid-cols-[minmax(0,1fr)] gap-3 md:grid-cols-2"><Side p={p.a} /><Side p={p.b} /></div>
            </li>))}</ul>)}
        <p className="mt-2 text-[11px] text-slate-500">{data.limitations}</p>
      </>)}
    </Card>
  );
}
