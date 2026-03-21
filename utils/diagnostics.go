package utils

// buildVendorDiagnostics summarizes per-integration cache and status outcomes
// from a ScanResult so the legacy API responses can expose lightweight
// diagnostics without leaking the full orchestrator shape.
func buildVendorDiagnostics(sr *ScanResult) map[string]VendorDiagnostic {
	if sr == nil {
		return nil
	}

	names := make(map[string]struct{})
	for name := range sr.Results {
		names[name] = struct{}{}
	}
	for name := range sr.Errors {
		names[name] = struct{}{}
	}
	for name := range sr.CacheHits {
		names[name] = struct{}{}
	}
	if len(names) == 0 {
		return nil
	}

	out := make(map[string]VendorDiagnostic, len(names))
	for name := range names {
		diag := VendorDiagnostic{
			Cache: "live",
		}
		if sr.CacheHits != nil && sr.CacheHits[name] {
			diag.Cache = "hit"
		}

		if errMsg, hasErr := sr.Errors[name]; hasErr {
			diag.Status = "error"
			diag.Error = errMsg
			out[name] = diag
			continue
		}

		if fields, ok := sr.Results[name]; ok {
			if status := strField(fields, "queryStatus"); status != "" {
				diag.Status = status
			} else {
				diag.Status = "ok"
			}
			out[name] = diag
			continue
		}

		diag.Status = "unknown"
		out[name] = diag
	}

	return out
}
