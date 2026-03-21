/**
 * scanStorage — persists the latest AgenticReport to localStorage so the
 * Governance Dashboard can read it without needing React state passed between
 * pages.
 *
 * Key: "threatlens-last-scan"
 * Value: JSON { owner, repo, report, savedAt }
 */

import type { AgenticReport } from "./agenticScan";

const STORAGE_KEY = "threatlens-last-scan";

export interface StoredScan {
	owner: string;
	repo: string;
	report: AgenticReport;
	savedAt: number;
}

export function saveLastScan(owner: string, repo: string, report: AgenticReport): void {
	try {
		const payload: StoredScan = {
			owner,
			repo,
			// Dates don't survive JSON round-trips cleanly — normalise to ISO string
			report: {
				...report,
				scannedAt: report.scannedAt,
			},
			savedAt: Date.now(),
		};
		localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
	} catch {
		// Storage quota exceeded or private-browsing restriction — silently ignore
	}
}

export function loadLastScan(): StoredScan | null {
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		if (!raw) return null;
		const parsed = JSON.parse(raw) as StoredScan;
		// Re-hydrate Date
		parsed.report.scannedAt = new Date(parsed.report.scannedAt);
		return parsed;
	} catch {
		return null;
	}
}

export function clearLastScan(): void {
	try {
		localStorage.removeItem(STORAGE_KEY);
	} catch {
		// ignore
	}
}
