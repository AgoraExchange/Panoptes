# Panoptes

Panoptes is a real-time global intelligence dashboard managed by Agora Exchange. It aggregates live flight tracking, CCTV networks, earthquake monitoring, conflict zone mapping, satellite tracking, cyber reconnaissance tools, market signals, and 24/7 news feeds into a single GPU-accelerated interface.

This project is based on the open-source Osiris project by simplifaisoul and keeps the same core architecture while rebranding the product for Agora Exchange.

## Key Capabilities

| Domain | Data Points | Sources |
| --- | --- | --- |
| Aviation | Commercial, private, military, jets | OpenSky Network |
| Maritime | Global ports and chokepoints | Static naval intelligence |
| CCTV | Worldwide traffic and live cameras | TfL, WSDOT, Caltrans, NYC DOT, VicRoads, and more |
| Seismic | Real-time M2.5+ | USGS Earthquake API |
| Fires | Active hotspots | NASA FIRMS |
| News | 24/7 live streams | Global broadcasters |
| Weather | Severe events | NASA EONET |
| Space | Solar weather and satellites | NOAA SWPC, N2YO |
| Cyber | CVE threats and reconnaissance | NVD and built-in OSINT tools |
| Conflict | Active zones and tension maps | Static OSINT intelligence |

## Quick Start

```bash
npm install
npm run dev
```

Open http://localhost:3000.

## Environment Variables

Create a `.env.local` file when you want enhanced live data:

```env
# Optional - enhances flight data
OPENSKY_USERNAME=your_username
OPENSKY_PASSWORD=your_password

# Optional - satellite tracking
N2YO_API_KEY=your_key
```

Most features work without API keys. Data sources that need missing credentials are skipped gracefully.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Framework | Next.js 16 App Router |
| Language | TypeScript 5 |
| Map Engine | MapLibre GL JS |
| Animations | Framer Motion |
| Icons | Lucide React |
| Styling | Custom CSS |

## License And Attribution

Managed by Agora Exchange.

Based on the open-source Osiris project by simplifaisoul.
