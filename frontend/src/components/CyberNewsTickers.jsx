import { useEffect, useState } from "react";
import "./CyberNewsTickers.css";

const FEEDS = {
  attacks: {
    label: "GLOBAL CYBER ATTACKS",
    rss: "https://www.cshub.com/rss-feeds/attacks",
    color: "#c9a227",
  },
  hackerNews: {
    label: "THE HACKER NEWS",
    rss: "https://feeds.feedburner.com/TheHackersNews",
    color: "#8a8f98",
  },
};

function Ticker({ feed }) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    let isActive = true;

    async function loadNews() {
      try {
        const apiUrl = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(
          feed.rss,
        )}&count=15`;

        const response = await fetch(apiUrl);
        const data = await response.json();

        if (!isActive) {
          return;
        }

        if (data.status === "ok" && Array.isArray(data.items)) {
          setItems(data.items);
          setError(false);
        } else {
          setItems([]);
          setError(true);
        }
      } catch {
        if (isActive) {
          setItems([]);
          setError(true);
        }
      }
    }

    loadNews();

    const refreshInterval = setInterval(loadNews, 15 * 60 * 1000);

    return () => {
      isActive = false;
      clearInterval(refreshInterval);
    };
  }, [feed.rss]);

  return (
    <div className="cyber-ticker">
      <span
        className="cyber-ticker-label"
        style={{ backgroundColor: feed.color }}
      >
        {feed.label}
      </span>

      <div className="cyber-ticker-track">
        {error && (
          <span className="cyber-ticker-item">
            News feed temporarily unavailable.
          </span>
        )}

        {!error && items.length === 0 && (
          <span className="cyber-ticker-item">
            Loading cybersecurity updates…
          </span>
        )}

        {!error &&
          items.map((item) => (
            <span className="cyber-ticker-item" key={item.link || item.title}>
              <a href={item.link} target="_blank" rel="noopener noreferrer">
                {item.title}
              </a>
            </span>
          ))}
      </div>
    </div>
  );
}

export default function CyberNewsTickers() {
  return (
    <div className="cyber-news-tickers">
      <Ticker feed={FEEDS.attacks} />
      <Ticker feed={FEEDS.hackerNews} />
    </div>
  );
}
