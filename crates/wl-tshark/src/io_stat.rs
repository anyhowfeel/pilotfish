//! `io_series`: all graph series of the I/O graph in ONE `tshark -q -z io,stat` pass.

use std::path::Path;

use wl_model::{CaptureError, IoGraph, IoSeries, IoSpec};

use crate::error::from_stderr;
use crate::io_stat_parse::{calcs, parse_io_stat};
use crate::process::{self, Tools};

/// Smallest interval tshark handles sensibly (and the UI offers).
const MIN_INTERVAL: f64 = 0.001;

/// `io,stat` splits its arguments on commas and has no escaping, so a comma in a filter would
/// silently change its meaning.
fn check_filter(spec: &IoSpec) -> Result<(), CaptureError> {
    if spec.filter.contains([',', '\n', '\r']) {
        return Err(CaptureError::BadFilter(
            "commas are not supported in graph filters; use || between values".into(),
        ));
    }
    Ok(())
}

/// The `-z` argument for `specs`.
pub fn stat_arg(specs: &[IoSpec], interval: f64) -> String {
    let calcs: Vec<String> = specs.iter().flat_map(calcs).collect();
    format!("io,stat,{interval},{}", calcs.join(","))
}

fn run_pass(
    tools: &Tools,
    file: &Path,
    specs: &[IoSpec],
    interval: f64,
    opts: &[String],
) -> Result<IoGraph, CaptureError> {
    let mut args: Vec<String> = vec!["-r".into(), file.to_string_lossy().into_owned()];
    args.extend(opts.iter().cloned());
    args.extend(["-q".into(), "-z".into(), stat_arg(specs, interval)]);
    let out = process::run(&tools.tshark, &args)?;
    if !out.status.success() {
        return Err(from_stderr(&String::from_utf8_lossy(&out.stderr)));
    }
    Ok(parse_io_stat(
        &String::from_utf8_lossy(&out.stdout),
        specs,
        interval,
    ))
}

/// One pass for all series. If it fails (typically one bad filter) every series is retried alone
/// so only the broken one reports an error and the others still draw.
pub fn io_series(
    tools: &Tools,
    file: &Path,
    specs: &[IoSpec],
    interval: f64,
    opts: &[String],
) -> Result<IoGraph, CaptureError> {
    let interval = if interval.is_finite() {
        interval.max(MIN_INTERVAL)
    } else {
        1.0
    };
    let valid: Vec<bool> = specs.iter().map(|s| check_filter(s).is_ok()).collect();
    let ok_specs: Vec<IoSpec> = specs
        .iter()
        .zip(&valid)
        .filter(|(_, v)| **v)
        .map(|(s, _)| s.clone())
        .collect();
    if ok_specs.is_empty() {
        return Ok(failures(specs, interval, 0.0, |s| check_filter(s).err()));
    }
    let mut graph = match run_pass(tools, file, &ok_specs, interval, opts) {
        Ok(g) => g,
        Err(_) if ok_specs.len() > 1 => isolate(tools, file, &ok_specs, interval, opts)?,
        Err(e) => return Err(e),
    };
    // Re-insert placeholders for the specs rejected up front, keeping the requested order.
    let mut done = std::mem::take(&mut graph.series).into_iter();
    graph.series = specs
        .iter()
        .zip(&valid)
        .map(|(s, v)| match (v, check_filter(s)) {
            (true, _) => done.next().unwrap_or_default(),
            (false, Err(e)) => error_series(&e),
            (false, Ok(())) => IoSeries::default(),
        })
        .collect();
    Ok(graph)
}

fn error_series(e: &CaptureError) -> IoSeries {
    IoSeries {
        error: Some(e.to_string()),
        ..IoSeries::default()
    }
}

fn failures(
    specs: &[IoSpec],
    interval: f64,
    duration: f64,
    err: impl Fn(&IoSpec) -> Option<CaptureError>,
) -> IoGraph {
    IoGraph {
        interval,
        duration,
        series: specs
            .iter()
            .map(|s| err(s).map(|e| error_series(&e)).unwrap_or_default())
            .collect(),
    }
}

/// Runs each spec on its own; failures become per-series errors.
fn isolate(
    tools: &Tools,
    file: &Path,
    specs: &[IoSpec],
    interval: f64,
    opts: &[String],
) -> Result<IoGraph, CaptureError> {
    let mut graph = IoGraph {
        interval,
        ..IoGraph::default()
    };
    let mut any_ok = false;
    let mut last_err = None;
    for spec in specs {
        match run_pass(tools, file, std::slice::from_ref(spec), interval, opts) {
            Ok(mut g) => {
                any_ok = true;
                graph.duration = g.duration;
                graph.series.append(&mut g.series);
            }
            Err(e) => {
                graph.series.push(error_series(&e));
                last_err = Some(e);
            }
        }
    }
    match (any_ok, last_err) {
        (false, Some(e)) => Err(e),
        _ => Ok(graph),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wl_model::DeltaStat;

    #[test]
    fn builds_one_arg_with_all_columns() {
        let specs = [
            IoSpec {
                filter: String::new(),
                delta: None,
            },
            IoSpec {
                filter: "dns".into(),
                delta: Some(DeltaStat::Max),
            },
        ];
        assert_eq!(
            stat_arg(&specs, 0.1),
            "io,stat,0.1,COUNT(frame)frame,SUM(frame.len)frame.len,\
             COUNT(frame)frame&&(dns),SUM(frame.len)frame.len&&(dns),\
             MAX(frame.time_delta)frame.time_delta&&(dns)"
        );
    }

    #[test]
    fn commas_are_rejected_per_series() {
        let bad = IoSpec {
            filter: "tcp.port in {80,443}".into(),
            delta: None,
        };
        assert!(check_filter(&bad).is_err());
        let g = failures(&[bad], 1.0, 0.0, |s| check_filter(s).err());
        assert!(g.series[0].error.as_deref().unwrap().contains("commas"));
    }
}
