package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	tele "gopkg.in/telebot.v3"
)

// startReportScheduler launches a goroutine that sends daily traffic reports at 22:00 local time.
func (b *Bot) startReportScheduler() {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 19, 0, 0, 0, now.Location())
			if !next.After(now) {
				next = next.Add(24 * time.Hour)
			}
			time.Sleep(time.Until(next))

			b.sendDailyReport()
		}
	}()
	log.Println("Планировщик отчётов запущен (ежедневно в 19:00)")
}

// clientTraffic holds traffic info for one client in the report.
type clientTraffic struct {
	Name  string
	Bytes int64
}

func (b *Bot) sendDailyReport() {
	cfg := b.cfg.Get()

	for srvIdx, srv := range cfg.Servers {
		if len(srv.ReportUIDs) == 0 {
			continue
		}
		peers, err := AWGShowDump(srv)
		if err != nil {
			log.Printf("Отчёт: ошибка получения трафика с %s: %v", srv.Name, err)
			// Send error to server's report recipients
			errText := fmt.Sprintf("📈 Ежедневный отчёт (%s)\n\n❌ %s: ошибка получения данных",
				time.Now().Format("02.01.2006"), srv.Name)
			for _, uid := range srv.ReportUIDs {
				b.bot.Send(&tele.Chat{ID: uid}, errText)
			}
			continue
		}

		// Build current snapshot: pubKey -> rx+tx
		currentSnap := make(map[string]int64)
		for _, p := range peers {
			currentSnap[p.PubKey] = p.Rx + p.Tx
		}

		// Get previous snapshot
		prevSnap := b.state.GetTrafficSnapshot(srvIdx)

		// Get client names
		clients, _ := ListClients(srv)
		nameMap := make(map[string]string) // pubKey -> name
		for _, cl := range clients {
			nameMap[cl.ClientID] = cl.UserData.ClientName
		}

		// Calculate daily traffic per client
		var totalBytes int64
		var clientStats []clientTraffic

		for pubKey, curTotal := range currentSnap {
			var daily int64
			if prevSnap != nil {
				if prevTotal, ok := prevSnap.Peers[pubKey]; ok {
					daily = curTotal - prevTotal
					if daily < 0 {
						daily = curTotal // interface was restarted
					}
				} else {
					daily = curTotal // new client since last snapshot
				}
			} else {
				daily = curTotal // no previous snapshot
			}

			totalBytes += daily
			name := nameMap[pubKey]
			if name == "" {
				name = pubKey[:8] + "..."
			}
			clientStats = append(clientStats, clientTraffic{Name: name, Bytes: daily})
		}

		// Save current snapshot for next report
		b.state.SetTrafficSnapshot(srvIdx, &TrafficSnapshot{
			Time:  time.Now().Format(time.RFC3339),
			Peers: currentSnap,
		})

		// Build server report
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("📈 Ежедневный отчёт (%s)\n\n", time.Now().Format("02.01.2006")))
		sb.WriteString(fmt.Sprintf("📊 %s\n", srv.Name))
		sb.WriteString(fmt.Sprintf("Всего за сутки: %s\n", formatBytes(totalBytes)))
		sb.WriteString(fmt.Sprintf("Клиентов: %d\n", len(clientStats)))

		// Top 20% consumers
		if len(clientStats) > 0 {
			sort.Slice(clientStats, func(i, j int) bool {
				return clientStats[i].Bytes > clientStats[j].Bytes
			})
			topN := int(math.Ceil(float64(len(clientStats)) * 0.2))
			if topN < 1 {
				topN = 1
			}
			sb.WriteString(fmt.Sprintf("\n🔝 Топ %d (20%%):\n", topN))
			for i := 0; i < topN && i < len(clientStats); i++ {
				cs := clientStats[i]
				sb.WriteString(fmt.Sprintf("  %s — %s\n", cs.Name, formatBytes(cs.Bytes)))
			}
		}

		// Send to this server's report recipients
		text := sb.String()
		for _, uid := range srv.ReportUIDs {
			_, err := b.bot.Send(&tele.Chat{ID: uid}, text)
			if err != nil {
				log.Printf("Отчёт: ошибка отправки %d: %v", uid, err)
			}
		}
		log.Printf("Отчёт по %s отправлен %d получателям", srv.Name, len(srv.ReportUIDs))
	}

	if err := b.state.Save(); err != nil {
		log.Printf("Отчёт: ошибка сохранения state: %v", err)
	}
}

// formatBytes converts bytes to human-readable format.
func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
