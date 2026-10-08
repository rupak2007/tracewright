import { CustomChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";

import type { FindingOut } from "../api/client";
import { formatDuration, formatTime } from "../lib/format";

echarts.use([CustomChart, GridComponent, TooltipComponent, SVGRenderer]);

export interface Lane {
  /** unique lane id, e.g. "I-2/F-5" */
  key: string;
  incident: string;
  finding: FindingOut;
  /** true for findings of the open incident; linked incidents are drawn lighter */
  current: boolean;
}

export function lanesFor(
  incidents: { local_id: string; findings: FindingOut[] }[],
  currentId: string,
): Lane[] {
  const lanes = incidents.flatMap((inc) =>
    inc.findings.map((finding) => ({
      key: `${inc.local_id}/${finding.local_id}`,
      incident: inc.local_id,
      finding,
      current: inc.local_id === currentId,
    })),
  );
  return lanes.sort(
    (a, b) =>
      new Date(a.finding.start_ts).getTime() - new Date(b.finding.start_ts).getTime() ||
      a.key.localeCompare(b.key),
  );
}

/** Storyline: one swimlane per finding on a shared time axis (linked incidents included). */
export function Timeline({ lanes }: { lanes: Lane[] }) {
  const host = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const element = host.current;
    if (!element || lanes.length === 0) return;
    const chart = echarts.init(element, undefined, {
      renderer: "svg",
      width: element.clientWidth || 900,
      height: 60 + lanes.length * 34,
    });
    const rows = lanes.map((l) => `${l.key} ${l.finding.type}`);
    chart.setOption({
      animation: false,
      useUTC: true,
      grid: { left: 190, right: 24, top: 12, bottom: 36 },
      tooltip: {
        trigger: "item",
        // text only: the formatter returns plain strings built from detector metadata
        formatter: (p: { data: { lane: string; span: string } }) => `${p.data.lane}\n${p.data.span}`,
      },
      xAxis: { type: "time", axisLabel: { hideOverlap: true } },
      yAxis: { type: "category", inverse: true, data: rows, axisTick: { show: false } },
      series: [
        {
          type: "custom",
          encode: { x: [1, 2], y: 0 },
          data: lanes.map((l, i) => ({
            value: [i, new Date(l.finding.start_ts).getTime(), new Date(l.finding.end_ts).getTime()],
            lane: `${l.key} ${l.finding.type} (${l.finding.confidence})`,
            span: `${formatTime(l.finding.start_ts)} · ${formatDuration(l.finding.start_ts, l.finding.end_ts)}`,
            itemStyle: { opacity: l.current ? 1 : 0.45 },
          })),
          renderItem: (
            _params: unknown,
            api: {
              value: (i: number) => number;
              coord: (v: [number, number]) => [number, number];
              size: (v: [number, number]) => [number, number];
              style: () => object;
            },
          ) => {
            const lane = api.value(0);
            const start = api.coord([api.value(1), lane]);
            const end = api.coord([api.value(2), lane]);
            const height = api.size([0, 1])[1] * 0.55;
            return {
              type: "rect",
              shape: { x: start[0], y: start[1] - height / 2, width: Math.max(end[0] - start[0], 4), height },
              style: api.style(),
            };
          },
        },
      ],
    });
    return () => chart.dispose();
  }, [lanes]);

  if (lanes.length === 0) return <p className="muted">No findings to place on a timeline.</p>;
  return (
    <section aria-label="Storyline timeline">
      <div ref={host} className="timeline" role="img" aria-label={`Timeline of ${lanes.length} findings`} />
      <details>
        <summary>Timeline as a table</summary>
        <table>
          <thead>
            <tr>
              <th scope="col">Finding</th>
              <th scope="col">Type</th>
              <th scope="col">Start</th>
              <th scope="col">Duration</th>
            </tr>
          </thead>
          <tbody>
            {lanes.map((l) => (
              <tr key={l.key}>
                <th scope="row">{l.key}</th>
                <td>{l.finding.type}</td>
                <td>{formatTime(l.finding.start_ts)}</td>
                <td>{formatDuration(l.finding.start_ts, l.finding.end_ts)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </section>
  );
}
