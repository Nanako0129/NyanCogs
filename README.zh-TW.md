[English](README.md) | **繁體中文**

# NyanCogs

供 [Red Discord Bot](https://github.com/Cog-Creators/Red-DiscordBot) 使用的 Cog。

| Cog | 功能說明 |
|---|---|
| [ChannelSummary](#channelsummary) | 透過相容 OpenAI 介面的 LLM Agent 產生存有出處引註的頻道摘要 |
| [MessageWatch](#messagewatch) | 監控並向管理頻道通報疑似詐騙與敵意衝突的對話 |
| [EmbedFixer](#embedfixer) | 將支援的社群平台連結替換為第三方修復後的預覽連結 |
| [SpotifyPlaylist](#spotifyplaylist) | 讓 Audio 重新能播 Spotify 歌單連結 |

MessageWatch 的架構設計筆記收錄於 [`docs/`](docs/)，提供英文與繁體中文版本。

## ChannelSummary

ChannelSummary 透過相容 OpenAI 介面的 LLM Agent 產生存有出處引註的 Discord 頻道摘要。支援三種訊息範圍：近期訊息、指定起點與時間區間。Agent 僅能在觸發指令的該頻道內搜尋歷史訊息，無法跨頻道讀取；所選設定檔支援時，亦可使用 OpenAI 或 OpenRouter 的原生網路搜尋。一般的 Responses 與 Chat/CLIProxy 設定檔則可改用應用程式端控制的 Firecrawl 雲端工具。

### 安裝方式

```text
[p]cog install NyanCogs channelsummary
[p]load channelsummary
```

接著由 bot owner 建立一至多組全域 provider 設定檔。設定檔僅儲存端點（endpoint）、dialect、token 服務名稱以及模型許可清單等詮釋資料；API 金鑰則統一保存在 Red 共用的 API token 儲存庫中。

```text
[p]summary provider add openai openai_responses https://api.openai.com channelsummary_openai gpt-5.6
[p]summary provider key openai

[p]summary provider add openrouter openrouter_responses https://openrouter.ai channelsummary_openrouter openai/gpt-5.6
[p]summary provider key openrouter

[p]summary provider webkey
[p]summary provider webquota 20
```

### 網路搜尋

`web_enabled` 是伺服器層級的總開關。`web_mode` 用於選取搜尋後端，執行階段不會在不同後端間自動切換退避。

| `web_mode` | 行為 |
|---|---|
| `auto` | OpenAI／OpenRouter 使用原生託管搜尋；其餘設定檔在配有獨立金鑰時使用 Firecrawl |
| `native` | 使用 provider 自帶的原生託管搜尋 |
| `firecrawl` | 使用應用程式端控制的 Firecrawl 雲端工具 |

每次摘要最多可嘗試呼叫 5 次 Firecrawl，且無論伺服器設定多高，每次摘要最多僅提供 5 筆搜尋結果；擷取的 Markdown 內容則受限於 `web_fetch_max_chars`。

> ⚠️ **HTTP provider 會在網路上以明文傳輸金鑰。**

HTTP 傳輸僅限於 RFC1918、IPv6 ULA 或 loopback 目標位址。使用 HTTP provider 時，API 金鑰、特定 Discord 資料以及內嵌的圖片位元組皆會未經加密通過區域網路。請僅在受信任的 LAN 環境使用 HTTP，並盡可能優先採用 HTTPS。

### 設定方式

具備伺服器層級「管理訊息」權限的成員，可透過 `/summary settings` 選取設定檔與模型、利用選單與 Modal 彈出視窗調整各項限制、檢閱資料匯出揭露條款，並啟用本 cog。純文字指令介面為 `[p]summaryset set <key> <value>`；`[p]summary help` 則列出所有設定鍵值、範圍限制、provider 指令與隱私細節。

摘要預設會以該批訊息的主要語言撰寫。若需強制指定語言，可設定 `summary_language`，傳入不含空格的單一識別字串，例如 `zh-TW`、`zh-Hant-TW` 或 `Japanese`。

### 指令列表

| 指令 | 用途 |
|---|---|
| `/summary auto [count]` | 摘要近期訊息，並自動向後搜尋自然的討論主題起點 |
| `/summary from <message>` | 從指定的同頻道訊息 ID 或連結開始摘要（含該起點訊息） |
| `/summary time <duration>` | 摘要指定時間區間內的訊息，如 `30m`、`2h` 或 `1d` |
| `/summary settings` | 開啟具備「管理訊息」權限者使用的選單與 Modal 設定面板 |
| `[p]summaryset show` | 顯示該伺服器目前生效的所有設定 |
| `[p]summaryset set <key> <value>` | 修改任何已記載於說明的文字設定項 |
| `[p]summaryset reset <key\|all>` | 重設單項設定或整座伺服器設定 |
| `[p]summaryset enable I_ACCEPT` / `[p]summaryset disable` | 在同意揭露條款後啟用，或停用頻道摘要功能 |
| `[p]summaryset checkpoint <show\|reset>` | 檢視或清除目前頻道的成功摘要檢查點 |

摘要生成期間，機器人會透過一則暫時性的頻道狀態顯示收集訊息、Agent 脈絡補全與 Embed 渲染的進度，完成後即行移除。進度文字絕不揭露隱藏的推理思維或工具原始酬載（payload）。

### 存取權限與速率限制

伺服器啟用本功能後，凡具備當前頻道檢視與讀取權限的使用者皆可執行摘要。機器人本體需要「檢視頻道」（View Channel）、「讀取訊息歷史」（Read Message History）、「發送訊息」（Send Messages）與「嵌入連結」（Embed Links）權限。

| 控制機制 | 效果 |
|---|---|
| 單一使用者冷卻時間 | 限制同一成員觸發摘要的頻率 |
| 伺服器請求配額（原子操作） | 限制整座伺服器的請求次數上限 |
| 伺服器／Provider 有界並行限制 | 限制同時執行的摘要數量 |
| 單一頻道新訊息檢查點 | 成功產生摘要後，該頻道必須累積 20 則真人新訊息才能再次執行摘要 |

具備伺服器層級「管理訊息」權限的成員不受檢查點限制，但仍受冷卻時間、配額與並行上限約束。

Embed 頁尾會列出該次摘要消耗的資源：input 與 output tokens，若 provider 有分開提供則包含 reasoning tokens，以及 provider 回傳的花費金額。OpenRouter 會回傳金額；OpenAI 則不會，且系統不會自本機計價表推算費用。

### 連結與提及安全性

摘要 Embed 保留通過驗證的 `<@user_id>` 發言者標註，但一律使用 `AllowedMentions.none()`，不會向任何人發出通知。渲染過程完全不在本機發起網路 I/O。

| 連結類型 | 權威來源 |
|---|---|
| Discord 跳轉連結 | 由傳入的訊息於本機直接構建 |
| 原生模式網路連結 | 僅限 provider 回傳之引註標註（Citation Annotations） |
| Firecrawl 模式網路連結 | 僅限同次執行中經應用程式驗證之 Firecrawl 成功搜尋結果 URL |

模型產生的文字註記與手動輸入的抓取 URL 不具任何權威效力。

### 圖片處理

啟用圖片支援時，機器人會下載每個附件，將長邊等比例縮放至不超過 `image_max_edge` 像素（預設為 3840）並重新編碼，再將位元組直接嵌入請求送出。任何 Discord CDN URL 皆不離開本機器人，且發送前會剔除相機 GPS 等 EXIF 詮釋資料。

| 限制項目 | 數值 |
|---|---|
| 單一附件上限 | 20 MiB 與 25 MP |
| 單次請求所有附件合計上限 | 50 MiB 與 100 MP |
| 納入考量的附件數 | 依時間順序取前 20 個符合條件者 |
| 單次請求附加之重新編碼位元組 | 最多 16 MB |

調低 `image_max_edge` 可在單次摘要中容納更多張圖片。

### 隱私

被選取的訊息文字、固定使用者與訊息 ID、時間戳記、回覆與 embed 詮釋資料會離開 Discord 發送給選定的 LLM。圖片內容最多可能跨越 20 次無狀態對話輪次反覆重傳給 LLM。在 Firecrawl 模式下，源自 Discord 私密發言的搜尋字詞與擷取 URL 會送往 Firecrawl；而 Firecrawl 回傳的 URL、標題、摘要內文與 Markdown 則會傳給 LLM，同樣最多可能在 20 輪對話中重傳。

供應商端對資料的保留與訓練政策尚未取得驗證。Firecrawl 的資料保留與訓練政策同樣未經驗證，且其點數可能產生費用。伺服器管理者同意後，凡具備頻道讀取權限者皆可觸發這些資料匯出。

> ⚠️ **所有伺服器共用 Firecrawl 的每小時配額。**

Bot owner 的 Firecrawl 每小時配額為全行程（process-wide）共用資源池；單一啟用的伺服器即可能耗盡所有伺服器的 Firecrawl 配額與支出額度；伺服器請求配額並非 owner 端的 Firecrawl 預算控管機制。重啟行程會清空記憶體中的資源池計數，而運行多個行程則會倍增此上限。

信任 Firecrawl 雲端服務能妥善控管目標 DNS、重新導向與 SSRF；DNS rebinding 與 split-horizon 行為仍屬殘留的廠商端風險。

ChannelSummary 不會持久化儲存訊息、prompt、搜尋內容、provider 回應或摘要結果。完整聲明請參閱 [`channelsummary/info.json`](channelsummary/info.json)。

## MessageWatch

MessageWatch 負責監控並向管理頻道通報疑似詐騙訊息與敵意衝突對話。它透過 [TypeSafe Jev](https://docs.typesafe.ai/) 評估近期訊息的短滾動視窗，該模型回傳校準後的機率值而非文字，且本 cog 絕不自主執行處置動作。

| 檔案 | 內容說明 |
|---|---|
| [`docs/messagewatch-design.zh-TW.md`](docs/messagewatch-design.zh-TW.md) · [English](docs/messagewatch-design.md) | 架構設計決策──記錄本 cog 為何採用此設計 |
| [`docs/jev-integration.zh-TW.md`](docs/jev-integration.zh-TW.md) · [English](docs/jev-integration.md) | 問題設計與各項判定門檻背後的實測數據 |

### 安裝方式

```text
[p]cog install NyanCogs messagewatch
[p]load messagewatch
[p]watch key                     # owner only, stores the TypeSafe api_key
[p]watch report #mod-log         # the guild-wide default
[p]watch route #樹洞 #樹洞管理    # one channel's reports, sent elsewhere
[p]watch disclosure              # read it
[p]watch disclosure I_ACCEPT
[p]watch enable #a-channel       # one channel at a time
```

每個頻道都必須個別啟用，未啟用前絕不發送任何資料。

> ⚠️ **啟用的頻道屬於常態性資料匯出。** 訊息文字會持續傳送至 TypeSafe，無需任何人主動觸發，這點與隨選執行的 `/summary` 不同。在樹洞或告解頻道中，這項特性的代價最高：成員在該處發言，正是預期這些文字不會外傳。

每次請求亦包含該頻道的名稱；若該頻道設定了版規，亦會包含其規則與用途說明。Discord 使用者 ID、顯示名稱與頭像絕不對外發送；發言者會替換為每次請求動態產生且不儲存的代稱（如 `u1`）。embed 與連結絕不下載或解析；圖片附件則僅在管理者開啟圖片讀取的頻道中才會下載。

`[p]watch disable` 會立即丟棄該頻道佇列中的所有待處理項目，並停止繼續讀取訊息。但該指令不會取消正在傳送途中的報告：它需要取得與 `flush` 相同的頻道鎖，會等待已開始的 flush 執行完畢，該次報告仍會正常送出。

### 通報按鈕

通報報告所附帶的按鈕配置為逐頻道獨立設定，預設僅包含兩顆標記按鈕。

```text
[p]watch action set #一般討論 ok no del      # marks plus delete
[p]watch action set #樹洞 ok no role         # marks plus a blacklist role
[p]watch action role #樹洞 @樹洞黑名單
[p]watch marks                               # what moderators have marked so far
```

| 按鈕 | 效果 | 點擊者必要權限 |
|---|---|---|
| `ok` | 記錄本通報判定屬實 | 無（僅需具備檢視管理頻道權限） |
| `no` | 記錄本通報判定為誤判 | 無（僅需具備檢視管理頻道權限） |
| `del` | 刪除被標記的訊息 | `manage_messages` |
| `mute` | 將作者暫時禁言 | `moderate_members` |
| `role` | 為作者加上設定的身分組 | `manage_roles` |

每次具體處置動作皆會以該管理員名義記錄於 Red 的 modlog 中，報告本體亦會附加一行說明由誰執行了何種動作。

`ok` 與 `no` 不會執行任何處置動作。它們僅記錄通報是否正確，這是本 cog 唯一能持續累積的精確率（precision）數據──程式中的所有門檻數值皆來自合成案例與手寫測試集的量測校準。

> **說明：** `[p]watch marks` 會印出這些計數，並明確指出它們衡量的是精確率而非召回率（recall）。本 cog 漏判的案例從未產生通報報告可供標記。

按鈕完全依自身 `custom_id` 運作，機器人重啟後舊報告上的按鈕仍可直接點擊，cog 亦無需在記憶體中保留待處理紀錄。

報告會註明來源頻道，個別頻道可透過 `[p]watch route` 將通報結果導向預設以外的地點。樹洞頻道的報告包含成員抒發的心事，能看見這些內容的人數應少於檢視一般詐騙警告的人數。未設定路由時，報告統一發送至伺服器預設的管理頻道。

### 圖片讀取

個別頻道可開啟圖片附件讀取功能，預設為關閉：

```text
[p]set api messagewatch_vision api_key <key>     # bot owner
[p]watch vision api_base https://openrouter.ai   # bot owner
[p]watch vision model <a model with image input> # bot owner
[p]watch images #一般討論 on                      # guild manager
```

提示詞僅要求逐字轉錄**圖片中的文字**，不要求畫面描述。這類詐騙多為含有文字的螢幕截圖，文字本身就是證據；畫面描述屬於開放式生成，出錯時難以對照圖片查驗。轉錄文字會直接併入既有的詐騙判定流程，無需另訂規則；報告中亦會顯示這段文字，因為模型擷取的文字未經校準。

> ⚠️ **轉錄文字會傳送兩次。** 它既會顯示於通報報告中，*亦會*連同訊息內文一併送往 TypeSafe，因此原本僅存在於圖片中的文字會同時抵達兩家服務商。

| 屬性 | 設定值 |
|---|---|
| 向視覺模型要求的內容 | 逐字轉錄圖片中的字元，不包含其他內容 |
| 發送前處理 | 縮小尺寸並重新編碼，藉此剔除包含 GPS 標籤在內的 EXIF 詮釋資料 |
| 快取機制 | 依 attachment id 於記憶體中最多快取 256 筆；絕不上碟儲存；重載或收到資料刪除請求時一併清空 |
| 預設模型 | 無──詳見下方說明 |
| 儀表板上的花費 | 讀供應商自己回報的 `usage`，不用價格表；BYOK 時 `cost` 為 0，改讀 `cost_details.upstream_inference_cost` |
| 端點通訊協定 | `https://` 不限主機，或 `http://` 加上 RFC1918／IPv6 ULA／loopback 的字面 IP |

本功能未提供預設模型。在未經實測評估何種模型判讀 CJK 螢幕截圖效果最佳前，貿然指定只是將猜測包裝成預設值；因此在完成設定模型與端點前，本 cog 不會發送任何圖片資料。

`[p]watch vision` 之所以與 `[p]watch set` 拆開，是因為後者只接受數值──即本 cog 的所有判定門檻──而這兩項設定皆為字串。兩者皆採全域儲存，且僅有 bot owner 具備寫入權限：調用視覺模型消耗的是 owner 持有的全域 API 金鑰，若允許加入的任何伺服器管理員自訂端點，對方就能將該 bearer token 與所有圖片導向自建的主機。至於各頻道的圖片讀取開關，則維持由負責規劃頻道的伺服器管理者自行決定。

> ⚠️ **這是本 cog 所發送最繁重的酬載，也是唯一發往 TypeSafe 以外服務商的資料。** 圖片可能包含人臉、文件或他人私密對話的截圖。此功能僅能逐頻道個別開啟，揭露條款中亦明確記載此事。

### 頻道專屬規則

頻道亦可依據該處張貼的專屬版規判定：

```text
[p]watch serverrule add 廣告或拉人：張貼推廣連結、招募或帶風向的邀約
[p]watch rule purpose #樹洞 這裡是倒垃圾的地方，發文的人要的是被聽見，不是被指導
[p]watch rule add #樹洞 下指導棋：告訴發文的人應該怎麼做、給建議或行動方案
[p]watch rule list #樹洞
```

`[p]watch serverrule` 設定的規則套用於**所有**被監看的頻道；`[p]watch rule` 加的則
只用於該頻道。兩者是累加的——伺服器那組排在頻道自己的前面，這也是同時讀過兩份張貼
規則的成員會有的預期，而穩定的前綴讓頻道自己的規則在伺服器規則增加時仍維持在可預期
的編號上。`[p]watch rule list` 會列出合併後的完整清單並標出繼承來的那幾條，因為那才
是通報裡引用的編號。

版規採逐頻道獨立設定，因為樹洞頻道的規範套用在提問發問頻道上會顯得荒謬。未設定規則的頻道會維持與該功能推出前完全相同的判定提問。規則文字會轉化為模型作答時的選項，而非作為對話內容的一部分讀取：選項標籤必須直接描述其選取的項目，且將規則排除在 state 之外也能防止成員在發言中偽造或竄改規則。

報告會具體指出違反的規則與對應訊息。若模型確認存在違規但無法斷定具體違反哪一條，報告會如實標示條文不確定，而非隨意挑選一條。純粹「討論」版規的發言（例如指出他人違規）由獨立提問直接否決，因為在張貼了版規的頻道中，這是最常見看似違規但實則合規的情形。

| 實測於 2026-09-20，`jev-1.13.0`，真實頻道規則集 | 結果 |
|---|---|
| 是否有任何違規（12 組保留測試案例） | 12/12 |
| 具體違反哪一條規則 | 11/12──漏判的一例位於相鄰兩條規則之間，屬真正意義上的邊界文句 |
| 5 則合規正常回覆中的偽陽性數 | 0 |

早期迭代過程中使用的 19 組案例不屬於獨立驗證依據。

### 斜線指令

所有指令皆同時提供斜線指令版本：`/watch enable`、`/watch rule add`、`/watch set`。Discord 介面會對未持有「管理伺服器」（Manage Server）權限的成員隱藏此指令樹，這屬於顯示層級的過濾──後端的實際權限檢查仍會照常執行。

> ⚠️ **在 bot owner 執行 `[p]slash enable` 與 `[p]slash sync` 之前，斜線指令不會出現。** 若未執行同步，指令雖已存在於 cog 內部，但在 Discord 介面上完全隱形，表現形式與功能故障無異。

### 設定與診斷

| 指令 | 用途 |
|---|---|
| `[p]watch set` | 印出所有設定項目的涵義、接受值以及目前設定值 |
| `[p]watch set <key>` | 說明該項特定設定 |
| `[p]watch set <key> <value>` | 修改該項設定值 |
| `[p]watch show` | 顯示各監控頻道狀態：待處理訊息數、上次判定時間，以及上次未採取動作的原因 |

`[p]watch set` 會印出具體意義而非單純的鍵名清單。在斜線指令中，設定鍵是以同一份對照表生成的下拉選單，不會出現指令拒絕的無效項目。

`[p]watch show` 是主要的診斷介面。若缺乏此介面，當通報頻道的權限遺失時，管理員只會以為本週恰好沒有任何違規，因為本 cog 的所有錯誤路徑皆採靜默回傳。各項失敗原因亦會記錄於 `red.nyancogs.messagewatch` 日誌中，僅記錄原因代碼而不包含訊息內文。

### 視窗判定時機

| 情境 | 行為 |
|---|---|
| 累積滿完整視窗 | 立即執行判定；連續視窗重疊一半，每則訊息都會在兩個視窗中被判定，橫跨邊界的交談仍會被一同評估 |
| 頻道在未滿額時陷入沉寂 | 超過 `idle_seconds`（預設 600 秒）未有新訊息後執行判定，最低門檻為兩則訊息 |
| 僅有一則訊息且無後續發言 | 不予判定──敵意屬於對話互動產生的性質，需等待第二則訊息 |
| `[p]watch set idle_seconds 0` | 關閉閒置掃描；僅在累積滿完整視窗時才執行判定 |

若沒有閒置掃描，安靜的頻道將永遠無法觸發判定：樹洞頻道的典型互動就是一則貼文加上兩則回覆後隨即沉寂，而這正是版規最需要保護的情境。

視窗大小（window size）、通報冷卻時間以及三項判定門檻皆為伺服器層級設定。

### 實測預設值

實測於 2026-09-20，對照模型為 `jev-1.13.0`。

| 訊號 | 正向案例 | 負向案例 |
|---|---|---|
| 詐騙 | 0.93 以上 | 0.08（發言內容為「提醒注意釣魚信件」） |
| 敵意 | 0.95 | 0.03（激烈的技術爭論） |

在目標伺服器的 97 則真實訊息樣本中，各項指標觀測到的最高值分別為 0.05、0.15 以及滿分 3 分中的 1.53，顯示預設門檻遠高於日常背景值。

> **說明：** 偽陰性未能量測。該樣本中未包含任何應予捕捉的詐騙或爭執，本 cog 的召回率（recall）尚未經過驗證。

## EmbedFixer

EmbedFixer 將支援的社群連結替換為由機器人本體發送的第三方修復連結。它絕不偽裝訊息作者、絕不刪除原始貼文，亦絕不自行構建 `discord.Embed`。在 Discord 確認第三方預覽產生後，本 cog 僅會隱藏原訊息上的 embed。

若能從來源 URL 安全推導出作者個人檔案，替換列會採用以下格式：

```text
[Source platform](fixed URL) • [@author](author profile) • [Provider](fixed URL)
```

來源平台與 provider 標籤皆連向同一個修復後 URL。標籤文字取自實際匹配的平台與 provider 名稱，並未寫死為 Twitter 或 FxTwitter。若來源 URL 無法推導出作者個人檔案（例如 Pixiv 作品網址），則會省略中間的作者連結。

### 環境需求與安裝方式

- Red Discord Bot 3.5.24 或更高版本
- Python 3.11 或更高版本
- 除 Red 既有相依套件外，無需額外安裝 Python 套件

透過 Red 的 Downloader 安裝本 cog：

```text
[p]repo add NyanCogs https://github.com/Nanako0129/NyanCogs
[p]cog install NyanCogs embedfixer
[p]load embedfixer
```

請將 `[p]` 替換為機器人的指令前綴。

### 權限需求

| 位置 | 必要權限 |
|---|---|
| 原訊息所在頻道 | 檢視頻道（View Channel）、讀取訊息歷史（Read Message History）、管理訊息（Manage Messages） |
| 替換訊息或集中轉發頻道 | 檢視頻道（View Channel）、發送訊息（Send Messages）、嵌入連結（Embed Links）、讀取訊息歷史（Read Message History） |
| 預設反應控制項 | 新增反應（Add Reactions）；若設定了自訂外部表情符號，則需使用外部表情符號（Use External Emojis） |

當原訊息與替換訊息位於同一個頻道時，兩列所需的權限皆必須具備。本 cog 不使用「管理 Webhook」（Manage Webhooks）權限。

伺服器設定指令需要管理員（Administrator）或「管理伺服器」（Manage Server）權限。一般成員在伺服器的頻道、身分組、網域與使用者規則允許下，可使用 `/fix`、`/extractmedia`、訊息快顯功能表，以及個人專屬的 `ignoreme`、`usermode` 和 `notify` 設定。

### 指令列表

| 指令 | 用途 |
|---|---|
| `[p]fix <link>` / `/fix` | 發送一般修復後的 provider 連結 |
| `[p]extractmedia <link>` / `/extractmedia` | 為支援的詮釋資料 provider 附加受限的媒體 URL |
| 訊息 → 應用程式 → Fix Embed | 修復既有訊息中的連結 |
| 訊息 → 應用程式 → Extract Media | 從既有訊息中擷取支援的媒體詮釋資料 |
| `[p]embedfixer` / `[p]ef` | 顯示目前生效的模式與基本狀態 |
| `[p]embedfixer ignoreme` | 自行選擇是否要讓個人訊息參與自動修復 |
| `[p]embedfixer usermode` | 選擇遵循或覆寫伺服器的發送模式 |
| `[p]embedfixer notify` | 切換一般反應通知的開關 |

完整管理員指令清單請參閱 `[p]help embedfixer`。內容包含功能啟用、發送模式、頻道與身分組規則、網域／provider 選取、刪除與輪替控制、集中轉發路由、媒體擷取頻道、選用貼文文字、防爆雷（Spoiler）政策、FxTwitter 翻譯、其他機器人能見度、忽略特定使用者、重設、匯入與匯出。

保留舊版模式名稱 `delete_and_resend` 以相容上游設定。在本 cog 中它不會刪除原訊息，其行為與 `resend` 完全相同，皆由機器人直接發送。僅有 `reply` 模式會改變機器人訊息的附著位置。

### 行為與限制

| 面向 | 行為 |
|---|---|
| 原訊息 | 絕不刪除；僅在確認替換後隱藏其 embed |
| 發送者身分 | 一律由機器人發送；不使用 Webhook、不複製頭像或使用者名稱 |
| 一般輸出 | 僅含連結的 Markdown 單列；由 Discord 產生第三方預覽 |
| 詮釋資料擷取 | 僅支援 Twitter/X、Pixiv 與 Bluesky |
| 媒體處理 | 僅輸出許可清單中的 HTTPS 媒體 URL；絕不下載、轉碼或上傳媒體位元組 |
| 翻譯功能 | 僅支援 FxTwitter 且語言代碼恰為兩個 ASCII 字母 |
| 集中轉發路由 | 僅限同伺服器的文字頻道；NSFW 內容絕不能轉發至非 NSFW 頻道 |
| 失敗處理 | 不安全或格式損毀的詮釋資料會自動退回一般修復連結；原訊息不予刪除 |
| 所有權控制 | 僅原作者能刪除或輪替符合條件的機器人替換訊息 |

設定為自動擷取的頻道仍會對其他支援的平台套用一般連結修復，不會抓取詮釋資料。主動觸發的 Extract Media 操作會直接拒絕 Twitter/X、Pixiv 與 Bluesky 以外的平台。

Kemono 媒體擷取、Webhook 偽裝身分、刪除原始訊息、下載 provider 媒體檔案，以及上游的資料庫與網頁儀表板，皆刻意不予納入。

### 隱私

本 cog 透過 Red Config 儲存伺服器與使用者設定，以及具備數量上限的純量替換訊息所有權紀錄。紀錄內容包含 ID、provider／網域識別字串與時間戳記，但不儲存訊息內文、完整 URL 或 provider 回應。

Provider 詮釋資料、選用的清理後貼文文字與媒體 URL 僅在擷取處理時暫存於記憶體中，本 cog 不會儲存、快取或將其寫入記錄檔。Red 的使用者資料刪除 hook 會一併清除該使用者的設定、所有權紀錄與通知節流狀態。完整資料處理聲明請參閱 [`embedfixer/info.json`](embedfixer/info.json)。

### 來源出處與授權條款

Provider 清單與轉換規則改編自 [`seriaati/embed-fixer`](https://github.com/seriaati/embed-fixer) 上游 commit [`42be298c49c3c3910859d1f27943abf9c4e95eb8`](https://github.com/seriaati/embed-fixer/tree/42be298c49c3c3910859d1f27943abf9c4e95eb8)。本 Red Cog 保留上游的 GPL-3.0 授權，並依本儲存庫的 [GPL-3.0 license](LICENSE) 散布。

## SpotifyPlaylist

Spotify 現在拒絕 Red Audio 使用的 client-credentials token 呼叫
`GET /v1/playlists/{id}/tracks`，Audio 3.5.24 因此把所有歌單連結都回成「This
doesn't seem to be a supported Spotify URL or code.」。單曲與專輯不受影響。

SpotifyPlaylist 包住 Audio 的 Spotify 用戶端。歌單曲目請求回傳錯誤時，改從
Spotify 公開的嵌入頁讀取歌單，再以 Web API 原本的資料格式交還 Audio，所以找
YouTube、排入佇列與快取仍由 Audio 自己處理。這個 cog 不儲存任何資料，也沒有指令。

嵌入頁不是公開文件記載的介面。Spotify 若改版或限制長度，備援會找不到曲目，
Audio 就會回到原本的錯誤訊息。

```text
[p]repo add NyanCogs https://github.com/Nanako0129/NyanCogs
[p]cog install NyanCogs spotifyplaylist
[p]load spotifyplaylist
[p]play https://open.spotify.com/playlist/<id>
```

需要先載入 Audio。Audio 重新載入時，這個 cog 會在 Audio 重新加入後，對新匯入的用戶端再套用一次。
