#!/usr/bin/env python3
"""Нагрузочная проверка Crumb: много одновременных «пользователей» и замер времени ответа.

Нужен только Python 3, больше ничего ставить не надо.

  python3 tools/loadtest.py --url https://ВАШ-АДРЕС.workers.dev --users 50 --rounds 5

Что делает каждый «пользователь» за круг: открывает страницу, запрашивает /api/health и настройки
уведомлений, при --ai ещё просит ИИ-проверку (самый дешёвый запрос). Отдельно можно проверить аккаунты:
--accounts создаёт тестовые аккаунты и гоняет синхронизацию данных, --logins запускает много входов
одновременно (хеширование пароля самое тяжёлое место). В конце тестовые аккаунты удаляются.

Осторожно с --ai: каждый запрос тратит общий бесплатный лимит Gemini и суточный лимит вашего IP (все
«пользователи» приходят с одного адреса, поэтому после 60 запросов будет 429, это нормально).
Регистраций с одного IP в сутки разрешено 5, поэтому --accounts не больше 5.
"""
import argparse
import json
import random
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.request

CTX = ssl.create_default_context()
LOCK = threading.Lock()
STATS = {}          # название запроса -> список (код, миллисекунды)
WHY = {}            # (запрос, код, причина) -> сколько раз
T_START = time.perf_counter()


def req(base, method, path, body=None, headers=None, timeout=40):
    data = json.dumps(body).encode() if body is not None else None
    h = {'user-agent': 'crumb-loadtest', 'accept': '*/*'}
    if data is not None:
        h['content-type'] = 'application/json'
    h.update(headers or {})
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    t0 = time.perf_counter()
    status, raw = 0, b''
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=CTX) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except ssl.SSLError as e:
        status = -2
        print('Ошибка сертификата (%s). На macOS попробуйте: /Applications/Python*/Install\\ Certificates.command' % e, file=sys.stderr)
    except Exception:
        status = 0                                   # нет связи или таймаут
    return status, (time.perf_counter() - t0) * 1000, raw


def rec(name, res):
    why = ''
    if res[0] == 0 or res[0] >= 400:
        why = str(jbody(res[2]).get('error') or ('нет связи' if res[0] == 0 else ''))
    with LOCK:
        STATS.setdefault(name, []).append((res[0], res[1]))
        if why:
            WHY[(name, res[0], why)] = WHY.get((name, res[0], why), 0) + 1
    return res


def jbody(raw):
    try:
        return json.loads(raw.decode() or '{}')
    except Exception:
        return {}


def pct(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round((len(xs) - 1) * p)))]


def rid(n=24):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def guest(base, i, a):
    """Гость: страница, health, настройки уведомлений, по желанию ИИ."""
    time.sleep(i * a.ramp / max(1, a.users))
    hdr = {'x-crumb-id': rid()}
    for _ in range(a.rounds):
        rec('страница /', req(base, 'GET', '/'))
        rec('/api/health', req(base, 'GET', '/api/health'))
        rec('/api/push/config', req(base, 'GET', '/api/push/config'))
        for _ in range(a.ai):
            rec('/api/ai (ping)', req(base, 'POST', '/api/ai', {'task': 'ping'}, hdr))
        time.sleep(random.uniform(0.2, 1.0))         # человек не жмёт без пауз


def ai_burst(base, barrier, text):
    """Один ИИ-запрос в общий старт: все потоки отправляют его в одну и ту же долю секунды."""
    hdr = {'x-crumb-id': rid()}                     # у каждого «человека» своё устройство, как в жизни
    barrier.wait()
    rec('ИИ (еда) одновременно', req(base, 'POST', '/api/ai', {'task': 'food', 'lang': 'ru', 'text': text}, hdr, timeout=70))


def state_blob():
    entries = [{'id': rid(7), 't': '12:00', 'type': 'meal', 'title': 'Тест ' + rid(5), 'kcal': 400, 'p': 20, 'f': 10, 'c': 50} for _ in range(60)]
    return json.dumps({'v': 2, 'onboarded': True, 'log': {'2026-01-%02d' % d: {'entries': entries[:5], 'water': 1500} for d in range(1, 29)}, 'weights': []})


def acct_agent(base, cred, rounds):
    st, ms, raw = rec('вход (аккаунт)', req(base, 'POST', '/api/auth/login', {'login': cred['login'], 'password': cred['password']}))
    tok = jbody(raw).get('token')
    if not tok:
        return
    cred['tokens'].append(tok)
    h = {'x-crumb-token': tok, 'x-crumb-id': rid()}
    for _ in range(rounds):
        rec('PUT /api/state', req(base, 'PUT', '/api/state', {'json': state_blob(), 'updatedAt': int(time.time() * 1000)}, h))
        rec('GET /api/state', req(base, 'GET', '/api/state', None, h))
        time.sleep(random.uniform(0.2, 0.8))


def login_burst(base, cred):
    st, ms, raw = rec('вход одновременно', req(base, 'POST', '/api/auth/login', {'login': cred['login'], 'password': cred['password']}))
    tok = jbody(raw).get('token')
    if tok:
        cred['tokens'].append(tok)


def run_threads(fns):
    ts = [threading.Thread(target=f) for f in fns]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


def report(started):
    total = sum(len(v) for v in STATS.values())
    dur = time.perf_counter() - started
    print('\n%-22s %6s %7s %7s %8s %8s %8s' % ('запрос', 'всего', 'ошибок', 'лимит', 'p50 мс', 'p95 мс', 'макс мс'))
    bad_any = False
    for name, rows in STATS.items():
        ms = [m for s, m in rows]
        errs = sum(1 for s, m in rows if s == 0 or s >= 500 or (s >= 400 and s != 429))
        lim = sum(1 for s, m in rows if s == 429)
        print('%-22s %6d %7d %7d %8.0f %8.0f %8.0f' % (name, len(rows), errs, lim, pct(ms, .5), pct(ms, .95), max(ms)))
        slow = 20000 if 'ИИ' in name else 2500            # ИИ по природе медленнее: для него порог 20 с
        if errs or pct(ms, .95) > slow:
            bad_any = True
    print('\nВсего запросов: %d за %.1f с (%.1f в секунду).' % (total, dur, total / max(dur, .001)))
    codes = {}
    for rows in STATS.values():
        for s, m in rows:
            codes[s] = codes.get(s, 0) + 1
    print('Коды ответов:', ', '.join('%s×%d' % (k if k else 'нет связи', v) for k, v in sorted(codes.items())))
    if WHY:
        print('Причины отказов:')
        for (name, code, why), n in sorted(WHY.items(), key=lambda kv: -kv[1]):
            print('  %-24s код %s «%s» ×%d' % (name, code or '—', why, n))
        print('  (rate_limited: общий лимит запросов Gemini; limit_ip / limit_day / limit_global: лимиты самого приложения;')
        print('   upstream / timeout / empty: Gemini не ответил вовремя или отказал)')
    print('Вывод:', 'есть ошибки или медленные ответы (обычные запросы дольше 2,5 с, ИИ дольше 20 с), смотрите таблицу' if bad_any else 'ошибок нет, ответы быстрые')


def main():
    ap = argparse.ArgumentParser(description='Нагрузочная проверка Crumb')
    ap.add_argument('--url', required=True, help='адрес сайта, например https://crumby.имя.workers.dev')
    ap.add_argument('--users', type=int, default=50, help='сколько пользователей одновременно (по умолчанию 50)')
    ap.add_argument('--rounds', type=int, default=5, help='сколько кругов на каждого (по умолчанию 5)')
    ap.add_argument('--ramp', type=float, default=0, help='за сколько секунд плавно подключить всех (0 = одновременно)')
    ap.add_argument('--ai', type=int, default=0, help='ИИ-запросов (ping) на пользователя за круг, от 0 до 3')
    ap.add_argument('--ai-burst', type=int, default=0, help='сколько ИИ-запросов отправить в один момент посреди нагрузки (от 0 до 20)')
    ap.add_argument('--accounts', type=int, default=0, help='тестовых аккаунтов для проверки синхронизации, от 0 до 5')
    ap.add_argument('--logins', type=int, default=0, help='сколько входов одновременно (нужны --accounts)')
    ap.add_argument('--yes', action='store_true', help='подтвердить больше 100 пользователей')
    a = ap.parse_args()

    base = a.url.rstrip('/')
    if not base.startswith(('http://', 'https://')):
        sys.exit('Адрес должен начинаться с https://')
    a.ai = max(0, min(3, a.ai))
    a.ai_burst = max(0, min(20, a.ai_burst))
    a.accounts = max(0, min(5, a.accounts))
    if a.users > 100 and not a.yes:
        sys.exit('Больше 100 пользователей: добавьте --yes, если уверены.')
    if a.users * a.rounds * a.ai + a.ai_burst > 60:
        print('Внимание: ИИ-запросов будет больше 60, лимит вашего IP (60 в сутки) их отрежет, это нормально.')
    if a.logins and not a.accounts:
        sys.exit('--logins работает только вместе с --accounts.')

    print('Проверяю %s: %d пользователей × %d кругов, ИИ %d, ИИ одновременно %d, аккаунтов %d, одновременных входов %d' % (base, a.users, a.rounds, a.ai, a.ai_burst, a.accounts, a.logins))
    st, ms, raw = req(base, 'GET', '/api/health')
    h = jbody(raw)
    if st != 200:
        sys.exit('Сайт не отвечает на /api/health (код %s). Проверьте адрес.' % st)
    print('Сервер: ИИ %s, аккаунты %s. Первый ответ %.0f мс.\n' % ('включён' if h.get('ai') else 'выключен', 'есть' if h.get('accounts') else 'нет', ms))

    creds = []
    if a.accounts:
        pw = rid(14) + '-A9'
        for n in range(a.accounts):
            login = 'lt-%s-%d' % (rid(6).lower(), n)
            s, m, raw = req(base, 'POST', '/api/auth/register', {'login': login, 'password': pw}, {'x-crumb-id': rid()})
            j = jbody(raw)
            if s == 200:
                creds.append({'login': login, 'password': pw, 'tokens': [j['token']]})
            else:
                print('Не удалось создать тестовый аккаунт (%s %s). Дальше без него.' % (s, j.get('error', '')))
        print('Тестовых аккаунтов создано: %d' % len(creds))

    t0 = time.perf_counter()
    jobs = [(lambda i=i: guest(base, i, a)) for i in range(a.users)]
    jobs += [(lambda c=c: acct_agent(base, c, a.rounds)) for c in creds]
    if a.ai_burst:
        barrier = threading.Barrier(a.ai_burst)
        jobs += [(lambda: (time.sleep(0.8), ai_burst(base, barrier, 'яблоко и чашка чая без сахара'))) for _ in range(a.ai_burst)]
    run_threads(jobs)
    if creds and a.logins:
        run_threads([(lambda c=creds[k % len(creds)]: login_burst(base, c)) for k in range(a.logins)])
    report(t0)

    left = 0
    for c in creds:                                   # уборка: тестовые аккаунты не должны остаться
        done = False
        for tok in reversed(c['tokens']):             # у аккаунта не больше 10 живых сессий, пробуем свежие
            s, m, raw = req(base, 'POST', '/api/auth/delete', {'password': c['password']}, {'x-crumb-token': tok})
            if s == 200:
                done = True
                break
        if not done:
            left += 1
            print('Не удалось удалить тестовый аккаунт %s. Войдите под ним (пароль в начале запуска не показывается) или удалите позже.' % c['login'])
    if creds and not left:
        print('Тестовые аккаунты удалены.')


if __name__ == '__main__':
    main()
