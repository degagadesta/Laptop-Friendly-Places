<pre class="overflow-visible! px-0!" data-start="214" data-end="885"><div class="relative w-full mt-4 mb-1"><div class=""><div class="relative"><div class="h-full min-h-0 min-w-0"><div class="h-full min-h-0 min-w-0"><div class="border border-token-border-light border-radius-3xl corner-superellipse/1.1 rounded-3xl"><div class="h-full w-full border-radius-3xl bg-token-bg-elevated-secondary corner-superellipse/1.1 overflow-clip rounded-3xl lxnfua_clipPathFallback"><div class="pointer-events-none absolute inset-x-4 top-12 bottom-4"><div class="pointer-events-none sticky z-40 shrink-0 z-1!"><div class="sticky bg-token-border-light"></div></div></div><div class="relative"><div class=""><div class="relative z-0 flex max-w-full"><div id="code-block-viewer" dir="ltr" class="q9tKkq_viewer cm-editor z-10 light:cm-light dark:cm-light flex h-full w-full flex-col items-stretch ͼk ͼy"><div class="cm-scroller"><div class="cm-content q9tKkq_readonly"><span></span><br/><br/><span>## 📌 Overview</span><br/><span>The Favorites module allows authenticated users to manage their preferred laptop-friendly places. Users can:</span><br/><br/><span>- ⭐ Add places to favorites</span><br/><span>- 📋 View all saved favorite places</span><br/><span>- ❌ Remove places from favorites</span><br/><br/><span>This module is fully protected using **JWT authentication**.</span><br/><br/><span>---</span><br/><br/><span># 🔄 System Flow (How It Works)</span><br/><br/><span>## 👤 User Interaction Flow</span><br/><br/><span>```text</span><br/><span>User clicks "❤️ Favorite"</span><br/><span>        ↓</span><br/><span>add_favorite.php (Add place to favorites)</span><br/><span>        ↓</span><br/><span>User opens "My Favorites" page</span><br/><span>        ↓</span><br/><span>get_favorites.php (Fetch all favorites)</span><br/><span>        ↓</span><br/><span>User clicks "Remove"</span><br/><span>        ↓</span><br/><span>remove_favorite.php (Delete favorite)</span></div></div></div></div></div></div></div></div></div></div><div class=""><div class=""></div></div></div></div></div></pre>

---

# 🗄️ Database Design

## ⭐ favorites table (Conceptual View)

This table stores user-selected favorite places.

<pre class="overflow-visible! px-0!" data-start="1005" data-end="1123"><div class="relative w-full mt-4 mb-1"><div class=""><div class="relative"><div class="h-full min-h-0 min-w-0"><div class="h-full min-h-0 min-w-0"><div class="border border-token-border-light border-radius-3xl corner-superellipse/1.1 rounded-3xl"><div class="h-full w-full border-radius-3xl bg-token-bg-elevated-secondary corner-superellipse/1.1 overflow-clip rounded-3xl lxnfua_clipPathFallback"><div class="pointer-events-none absolute end-1.5 top-1 z-2 md:end-2 md:top-1"></div><div class="relative"><div class="pe-11 pt-3"><div class="relative z-0 flex max-w-full"><div id="code-block-viewer" dir="ltr" class="q9tKkq_viewer cm-editor z-10 light:cm-light dark:cm-light flex h-full w-full flex-col items-stretch ͼk ͼy"><div class="cm-scroller"><div class="cm-content q9tKkq_readonly"><span>favorites (</span><br/><span>    id (PK)</span><br/><span>    user_id (FK → users.id)</span><br/><span>    place_id (FK → places.id)</span><br/><span>    created_at (timestamp)</span><br/><span>)</span></div></div></div></div></div></div></div></div></div></div><div class=""><div class=""></div></div></div></div></div></pre>

---

## 💡 SQL Implementation

<pre class="overflow-visible! px-0!" data-start="1156" data-end="1638"><div class="relative w-full mt-4 mb-1"><div class=""><div class="relative"><div class="h-full min-h-0 min-w-0"><div class="h-full min-h-0 min-w-0"><div class="border border-token-border-light border-radius-3xl corner-superellipse/1.1 rounded-3xl"><div class="h-full w-full border-radius-3xl bg-token-bg-elevated-secondary corner-superellipse/1.1 overflow-clip rounded-3xl lxnfua_clipPathFallback"><div class="pointer-events-none absolute inset-x-4 top-12 bottom-4"><div class="pointer-events-none sticky z-40 shrink-0 z-1!"><div class="sticky bg-token-border-light"></div></div></div><div class="relative"><div class=""><div class="relative z-0 flex max-w-full"><div id="code-block-viewer" dir="ltr" class="q9tKkq_viewer cm-editor z-10 light:cm-light dark:cm-light flex h-full w-full flex-col items-stretch ͼk ͼy"><div class="cm-scroller"><div class="cm-content q9tKkq_readonly"><span class="ͼn">CREATE</span><span></span><span class="ͼn">TABLE</span><span> favorites (</span><br/><span>    id </span><span class="ͼt">INT</span><span></span><span class="ͼn">PRIMARY</span><span></span><span class="ͼn">KEY</span><span> AUTO_INCREMENT,</span><br/><span>    user_id </span><span class="ͼt">INT</span><span></span><span class="ͼn">NOT</span><span></span><span class="ͼq">NULL</span><span>,</span><br/><span>    place_id </span><span class="ͼt">INT</span><span></span><span class="ͼn">NOT</span><span></span><span class="ͼq">NULL</span><span>,</span><br/><span>    created_at </span><span class="ͼt">TIMESTAMP</span><span></span><span class="ͼn">DEFAULT</span><span></span><span class="ͼn">CURRENT_TIMESTAMP</span><span>,</span><br/><br/><span></span><span class="ͼl">-- Prevent duplicate favorites (same user cannot favorite same place twice)</span><br/><span></span><span class="ͼn">UNIQUE</span><span></span><span class="ͼn">KEY</span><span> unique_favorite (user_id, place_id),</span><br/><br/><span></span><span class="ͼl">-- Relationships</span><br/><span></span><span class="ͼn">FOREIGN</span><span></span><span class="ͼn">KEY</span><span> (user_id) </span><span class="ͼn">REFERENCES</span><span> users(id) </span><span class="ͼn">ON</span><span></span><span class="ͼn">DELETE</span><span></span><span class="ͼn">CASCADE</span><span>,</span><br/><span></span><span class="ͼn">FOREIGN</span><span></span><span class="ͼn">KEY</span><span> (place_id) </span><span class="ͼn">REFERENCES</span><span> places(id) </span><span class="ͼn">ON</span><span></span><span class="ͼn">DELETE</span><span></span><span class="ͼn">CASCADE</span><br/><span>);</span></div></div></div></div></div></div></div></div></div></div><div class=""><div class=""></div></div></div></div></div></pre>

---

# ⚙️ Key Design Explanation

### 🔹 id

Unique identifier for each favorite record.

### 🔹 user_id

Links to the user who saved the favorite.

### 🔹 place_id

Links to the place being favorited.

### 🔹 created_at

Stores when the favorite was added.

---

# 🔐 Authentication Requirement

All endpoints require JWT authentication:

<pre class="overflow-visible! px-0!" data-start="1976" data-end="2033"><div class="relative w-full mt-4 mb-1"><div class=""><div class="relative"><div class="h-full min-h-0 min-w-0"><div class="h-full min-h-0 min-w-0"><div class="border border-token-border-light border-radius-3xl corner-superellipse/1.1 rounded-3xl"><div class="h-full w-full border-radius-3xl bg-token-bg-elevated-secondary corner-superellipse/1.1 overflow-clip rounded-3xl lxnfua_clipPathFallback"><div class="pointer-events-none absolute inset-x-4 top-12 bottom-4"><div class="pointer-events-none sticky z-40 shrink-0 z-1!"><div class="sticky bg-token-border-light"></div></div></div><div class="relative"><div class=""><div class="relative z-0 flex max-w-full"><div id="code-block-viewer" dir="ltr" class="q9tKkq_viewer cm-editor z-10 light:cm-light dark:cm-light flex h-full w-full flex-col items-stretch ͼk ͼy"><div class="cm-scroller"><div class="cm-content q9tKkq_readonly"><span>Authorization: Bearer <JWT_TOKEN></span></div></div></div></div></div></div></div></div></div></div><div class=""><div class=""></div></div></div></div></div></pre>

Handled by:

<pre class="overflow-visible! px-0!" data-start="2047" data-end="2079"><div class="relative w-full mt-4 mb-1"><div class=""><div class="relative"><div class="h-full min-h-0 min-w-0"><div class="h-full min-h-0 min-w-0"><div class="border border-token-border-light border-radius-3xl corner-superellipse/1.1 rounded-3xl"><div class="h-full w-full border-radius-3xl bg-token-bg-elevated-secondary corner-superellipse/1.1 overflow-clip rounded-3xl lxnfua_clipPathFallback"><div class="pointer-events-none absolute end-1.5 top-1 z-2 md:end-2 md:top-1"></div><div class="relative"><div class="pe-11 pt-3"><div class="relative z-0 flex max-w-full"><div id="code-block-viewer" dir="ltr" class="q9tKkq_viewer cm-editor z-10 light:cm-light dark:cm-light flex h-full w-full flex-col items-stretch ͼk ͼy"><div class="cm-scroller"><div class="cm-content q9tKkq_readonly"><span>auth/auth.middleware.php</span></div></div></div></div></div></div></div></div></div></div></div></div></div></pre>
