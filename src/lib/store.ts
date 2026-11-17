'use client'
// DIVISION T82 — global UI store (view routing + language + cross-view selection)
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type ViewKey =
  | 'overview' | 'assets' | 'assessment' | 'findings' | 'network'
  | 'vulnintel' | 'hardening' | 'threatintel' | 'knowledge'
  | 'reports' | 'history' | 'integrations' | 'settings'

interface AppState {
  view: ViewKey
  lang: 'es' | 'en'
  selectedArticle: string | null
  selectedControl: string | null
  setView: (v: ViewKey) => void
  setLang: (l: 'es' | 'en') => void
  openArticle: (slug: string | null) => void
  setSelectedControl: (controlId: string | null) => void
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      view: 'overview',
      lang: 'es',
      selectedArticle: null,
      selectedControl: null,
      setView: (v) => set({ view: v }),
      setLang: (l) => set({ lang: l }),
      openArticle: (slug) => set({ selectedArticle: slug, view: 'knowledge' }),
      setSelectedControl: (controlId) => set({ selectedControl: controlId }),
    }),
    { name: 't82-ui-state' },
  ),
)
