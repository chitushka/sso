import { flushPromises, mount } from '@vue/test-utils'
import { createPinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import i18n from '../i18n'
import DashboardView from './DashboardView.vue'
import LoginView from './LoginView.vue'
import api from '../api'

vi.mock('../api', () => ({
  default: { get: vi.fn(), post: vi.fn() },
  apiError: vi.fn(() => 'Не удалось выполнить запрос.')
}))

async function mountPage(component, path = '/') {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: DashboardView },
      { path: '/login', component: LoginView },
      { path: '/forgot-password', component: { template: '<div />' } }
    ]
  })
  await router.push(path)
  await router.isReady()
  return mount(component, { global: { plugins: [createPinia(), router, i18n] } })
}

describe('критические страницы', () => {
  beforeEach(() => vi.clearAllMocks())

  it('показывает русскую форму входа', async () => {
    api.get.mockResolvedValue({ data: [] })
    const wrapper = await mountPage(LoginView, '/login')
    await flushPromises()
    expect(wrapper.text()).toContain('Вход в SSO')
    expect(wrapper.text()).toContain('Забыли пароль?')
  })

  it('показывает русскую панель и состояние API', async () => {
    api.get.mockImplementation((url) => {
      if (url === '/health/ready') return Promise.resolve({ data: { status: 'ok' } })
      return Promise.resolve({ data: [] })
    })
    const wrapper = await mountPage(DashboardView)
    await flushPromises()
    expect(wrapper.text()).toContain('Обзор')
    expect(wrapper.text()).toContain('API готов')
    expect(wrapper.text()).toContain('Пользователи')
  })
})
