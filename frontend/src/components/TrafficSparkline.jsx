export default function TrafficSparkline({ history = [] }) {
  if (!history.length) {
    return (
      <div className="traffic-empty">
        Waiting for usage samples
      </div>
    );
  }

  const values = history.map((point) => Number(point.total_delta || 0));
  const max = Math.max(...values, 1);
  const width = 220;
  const height = 56;

  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = height - ((value / max) * (height - 8)) - 4;
    return `${x},${y}`;
  }).join(' ');

  const areaPoints = `0,${height} ${points} ${width},${height}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="traffic-sparkline" role="img" aria-label="Recent traffic history">
      <defs>
        <linearGradient id="traffic-fill" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.38" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polyline points={areaPoints} fill="url(#traffic-fill)" stroke="none" />
      <polyline
        points={points}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
