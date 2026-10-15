import { describe, expect, it } from 'vitest'
import { apiError } from './api'

describe('локализация ошибок API', () => {
  it('не отражает произвольное сообщение сервера', () => {
    const error = { response: { status: 403, data: { error: 'forbidden', error_description: 'untrusted text' } } }
    expect(apiError(error)).toBe('Недостаточно прав для выполнения операции.')
  })

  it('сохраняет протокольный код ошибки без описания', () => {
    const error = { response: { status: 400, data: { error: 'invalid_scope' } } }
    expect(apiError(error)).toBe('invalid_scope')
  })

  it('не принимает обычное backend-сообщение за протокольный код', () => {
    const error = { response: { status: 400, data: { error: 'password is too short' } } }
    expect(apiError(error)).toBe('Проверьте введённые данные.')
  })
})
