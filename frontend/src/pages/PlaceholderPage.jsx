import { Clock, GitBranch } from 'lucide-react'
export default function PlaceholderPage({ phase, title, emba, branch, description }) {
  return (
    <div className="p-6">
      <div className="flex items-center gap-2 mb-1">
        <span className="badge badge-gray text-[10px]">Phase {phase} — Planned</span>
        <span className="text-gray-600 text-xs mono">{emba}</span>
      </div>
      <h1 className="text-2xl font-bold text-white">{title}</h1>
      <p className="text-gray-400 text-sm mt-1">{description}</p>
      <div className="mt-8 card max-w-md flex flex-col items-center py-12 text-center border-dashed">
        <Clock size={32} className="text-gray-700 mb-3" />
        <p className="text-gray-400 font-medium">Coming in Phase {phase}</p>
        <p className="text-gray-600 text-xs mt-1">Complete Phase {phase-1} first, then:</p>
        <div className="mt-4 flex items-center gap-1.5 text-xs text-gray-600 mono bg-gray-950 px-3 py-2 rounded-lg border border-gray-800">
          <GitBranch size={11} />
          <span>git checkout -b phase/{phase}-{branch}</span>
        </div>
      </div>
    </div>
  )
}
