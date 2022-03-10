/* eslint-env jest */
/* global browserName */
// @note taken from next.js testing suite, iframe starts at L#152
import webdriver from 'next-webdriver'
import { readFileSync } from 'fs'
import http from 'http'
import url from 'url'
import { join } from 'path'
import {
  renderViaHTTP,
  getBrowserBodyText,
  waitFor,
  fetchViaHTTP,
} from 'next-test-utils'

async function checkInjected(browser) {
  const start = Date.now()
  while (Date.now() - start < 5000) {
    const bodyText = await getBrowserBodyText(browser)
    if (/INJECTED/.test(bodyText)) {
      throw new Error('Vulnerable to XSS attacks')
    }
    await waitFor(500)
  }
}
module.exports = (context) => {
  describe('With Security Related Issues', () => {
    it('should handle invalid URL properly', async () => {
      async function invalidRequest() {
        return new Promise((resolve, reject) => {
          const request = http.request(
            {
              hostname: `localhost`,
              port: context.appPort,
              path: `*`,
            },
            (response) => {
              resolve(response.statusCode)
            }
          )
          request.on('error', (err) => reject(err))
          request.end()
        })
      }
      try {
        expect(await invalidRequest()).toBe(400)
        expect(await invalidRequest()).toBe(400)
      } catch (err) {
        // eslint-disable-next-line
        expect(err.code).toBe('ECONNREFUSED')
      }
    })

    it('should prevent URI based XSS attacks', async () => {
        const browser = await webdriver(
          context.appPort,
          '/\',document.body.innerHTML="INJECTED",\''
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using single quotes', async () => {
        const browser = await webdriver(
          context.appPort,
          `/'-(document.body.innerHTML='INJECTED')-'`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using double quotes', async () => {
        const browser = await webdriver(
          context.appPort,
          `/"-(document.body.innerHTML='INJECTED')-"`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using semicolons and double quotes', async () => {
        const browser = await webdriver(
          context.appPort,
          `/;"-(document.body.innerHTML='INJECTED')-"`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using semicolons and single quotes', async () => {
        const browser = await webdriver(
          context.appPort,
          `/;'-(document.body.innerHTML='INJECTED')-'`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using src', async () => {
        const browser = await webdriver(
          context.appPort,
          `/javascript:(document.body.innerHTML='INJECTED')`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using querystring', async () => {
        const browser = await webdriver(
          context.appPort,
          `/?javascript=(document.body.innerHTML='INJECTED')`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should prevent URI based XSS attacks using querystring and quotes', async () => {
        const browser = await webdriver(
          context.appPort,
          `/?javascript="(document.body.innerHTML='INJECTED')"`
        )
        await checkInjected(browser)
        await browser.close()
      })
      it('should handle encoded value in the pathname correctly \\', async () => {
        const res = await fetchViaHTTP(
          context.appPort,
          '/redirect/me/to-about/' + encodeURI('\\google.com'),
          undefined,
          {
            redirect: 'manual',
          }
        )
        const { pathname, hostname } = url.parse(
          res.headers.get('location') || ''
        )
        expect(res.status).toBe(307)
        expect(pathname).toBe(encodeURI('/\\google.com/about'))
        expect(hostname).toBe('localhost')
      })
      it('should handle encoded value in the pathname correctly %', async () => {
        const res = await fetchViaHTTP(
          context.appPort,
          '/redirect/me/to-about/%25google.com',
          undefined,
          {
            redirect: 'manual',
          }
        )
        const { pathname, hostname } = url.parse(
          res.headers.get('location') || ''
        )
        expect(res.status).toBe(307)
        expect(pathname).toBe('/%25google.com/about')
        expect(hostname).toBe('localhost')
      })

      
      it('should not execute iframe embedded inside svg image', async () => {
        let wasInvoked = false
        const server = http
          .createServer((req, res) => {
            const { method, pathname } = req
            res.setHeader('Access-Control-Allow-Credentials', 'true')
            res.setHeader('Access-Control-Allow-Origin', '*')
            res.setHeader('Access-Control-Allow-Headers', '*')
            if (method === 'OPTIONS') {
              res.end(200)
              return
            }
            wasInvoked = true
            console.log(JSON.stringify({ method, pathname }))
            res.end(JSON.stringify({ method, pathname }))
          })
          .listen(5243)
        try {
          const browser = await webdriver(
            context.appPort,
            '/_next/image?url=%2Fiframe.svg&w=256&q=75'
          )
          expect(await browser.elementById('iframe').getAttribute('src')).toBe(
            'http://127.0.0.1:5243/embed'
          )
          expect(wasInvoked).toBe(false)
        } finally {
          server.close()
        }
      })
    }
  )};
