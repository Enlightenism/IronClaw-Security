import { useEffect, useState } from "react";
import { cyberNews } from "@/lib/api";
import "./CyberNewsTickers.css";

const REFRESH_INTERVAL_MS = 15 * 60 * 1000;

const TICKERS = [
  {
    key: "attacks",
    label: "GLOBAL CYBER ATTACKS",
    color: "#c9a227",
  },
  {
    key: "hacker_news",
    label: "THE HACKER NEWS",
    color: "#8a8f98",
  },
  {
    key: "cisa",
    label: "CISA OFFICIAL ALERTS",
    color: "#d4af37",
  },
  {
    key: "bleeping_computer",
    label: "BREAKING SECURITY NEWS",
    color: "#c0c4c9",
  },
];

function TickerItems({ items, hidden = false }) {
  return (
    <div className="cyber-ticker-group" aria-hidden={hidden || undefined}>
      {items.map((item) => (
        <span className="cyber-ticker-item" key={`${item.link}-${item.title}`}>
          <a href={item.link} target="_blank" rel="noopener noreferrer">
            {item.title}
          </a>
        </span>
      ))}
    </div>
  );
}

function Ticker({ label, color, items, status }) {
  const hasItems = status === "ready" && items.length > 0;

  return (
    <div className="cyber-ticker" style={{ "--ticker-color": color }}>
      <span className="cyber-ticker-label">{label}</span>

      <div className="cyber-ticker-box">
        <div className={`cyber-ticker-track${hasItems ? " is-scrolling" : ""}`}>
          {status === "error" && (
            <span className="cyber-ticker-item">
              News feed temporarily unavailable.
            </span>
          )}

          {status === "loading" && (
            <span className="cyber-ticker-item">
              Loading cybersecurity updates…
            </span>
          )}

          {status === "ready" && items.length === 0 && (
            <span className="cyber-ticker-item">
              No current updates available.
            </span>
          )}

          {hasItems && (
            <>
              <TickerItems items={items} />
              <TickerItems items={items} hidden />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function CyberNewsTickers() {
  const [news, setNews] = useState({ status: "loading", feeds: {} });

  useEffect(() => {
    let isActive = true;

    async function loadNews() {
      try {
        const { data } = await cyberNews.get();

        if (!isActive) {
          return;
        }

        if (data?.feeds && typeof data.feeds === "object") {
          setNews({ status: "ready", feeds: data.feeds });
        } else {
          setNews({ status: "error", feeds: {} });
        }
      } catch {
        if (isActive) {
          setNews({ status: "error", feeds: {} });
        }
      }
    }

    loadNews();

    const refreshInterval = setInterval(loadNews, REFRESH_INTERVAL_MS);

    return () => {
      isActive = false;
      clearInterval(refreshInterval);
    };
  }, []);

  return (
    <div className="cyber-news-tickers">
      {TICKERS.map((ticker) => (
        <Ticker
          key={ticker.key}
          label={ticker.label}
          color={ticker.color}
          items={news.feeds[ticker.key] ?? []}
          status={news.status}
        />
      ))}
    </div>
  );
}
