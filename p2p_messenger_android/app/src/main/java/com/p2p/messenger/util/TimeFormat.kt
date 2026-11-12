package com.p2p.messenger.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * "(sent at: HH:MM day)" biçiminde mutlak
 * (göreli DEĞİL — bkz. ChatAdapter.formatTimestamp'in "5m ago"/"2h ago"
 * biçimi, o sohbet LİSTESİ satırları için ayrı bir amaca hizmet ediyor)
 * bir zaman damgası. Hem mesaj balonlarının (bkz. SimpleChatAdapter) HER
 * birinin altında HEM DE Ayarlar'daki bekleyen mesajlar listesinin (bkz.
 * PendingMessagesAdapter) "son deneme" sütununda kullanılan TEK, paylaşılan
 * biçimlendirme — ikisi de aynı görünmeli.
 */
fun formatAbsoluteTime(timestampMs: Long): String {
    if (timestampMs <= 0) return ""
    return SimpleDateFormat("HH:mm, d MMM", Locale.getDefault()).format(Date(timestampMs))
}
