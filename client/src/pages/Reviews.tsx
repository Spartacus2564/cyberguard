export default function Reviews() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">Reviews</h1>
        <p className="text-gray-500 text-sm mt-1">Peer review findings</p>
      </div>
      <div className="glow-line" />
      <div className="card p-12 text-center">
        <p className="text-gray-500">No reviews pending</p>
      </div>
    </div>
  );
}
