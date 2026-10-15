import { createI18n } from 'vue-i18n'

export const messages = {
  ru: {
    app: {
      title: 'Администрирование SSO', users: 'Пользователи', roles: 'Роли', groups: 'Группы', clients: 'OAuth-клиенты',
      ldap: 'LDAP', federation: 'Федерация', audit: 'Аудит', signOut: 'Выйти'
    },
    common: {
      save: 'Сохранить', cancel: 'Отмена', edit: 'Изменить', delete: 'Удалить', remove: 'Удалить', actions: 'Действия',
      name: 'Название', type: 'Тип', code: 'Код', description: 'Описание', enabled: 'Включён', yes: 'да', no: 'нет',
      filter: 'Применить', add: 'Добавить', status: 'Статус', source: 'Источник', email: 'Email', username: 'Имя пользователя',
      password: 'Пароль', firstName: 'Имя', lastName: 'Фамилия', emptyKeep: '(пусто — оставить текущее значение)'
    },
    errors: {
      request: 'Не удалось выполнить запрос.', invalid: 'Проверьте введённые данные.', unauthorized: 'Требуется вход в систему.',
      forbidden: 'Недостаточно прав для выполнения операции.', notFound: 'Запрошенный объект не найден.', conflict: 'Изменение конфликтует с текущим состоянием.',
      tooMany: 'Слишком много запросов. Повторите позже.', unavailable: 'Сервис временно недоступен.', server: 'Внутренняя ошибка сервера.'
    },
    login: {
      title: 'Вход в SSO', signingIn: 'Выполняется вход…', signIn: 'Войти', forgot: 'Забыли пароль?',
      continueWith: 'Продолжить через {provider}', mfaHelp: 'Введите шестизначный код из приложения-аутентификатора или код восстановления.',
      verify: 'Проверить', back: 'Назад', externalFailed: 'Внешний вход не выполнен. Повторите попытку или используйте пароль.',
      tooMany: 'Слишком много неудачных попыток. Повторите позже.', expired: 'Сеанс истёк. Войдите снова.', invalidCode: 'Неверный код.'
    },
    password: {
      resetTitle: 'Сброс пароля', resetSent: 'Если учётная запись существует, ссылка для сброса отправлена на её email.',
      loginLabel: 'Имя пользователя или email', sendLink: 'Отправить ссылку', backToLogin: 'Вернуться ко входу',
      newTitle: 'Новый пароль', new: 'Новый пароль', repeat: 'Повторите пароль', save: 'Сохранить пароль', mismatch: 'Пароли не совпадают.'
    },
    verifyEmail: {
      title: 'Подтверждение email', working: 'Проверяем…', ok: 'Email подтверждён. Эту страницу можно закрыть.',
      failed: 'Ссылка недействительна или устарела.', login: 'Перейти ко входу'
    },
    consent: {
      title: 'Доступ приложения', requests: '{client} запрашивает доступ к:', granted: 'уже разрешено', allow: 'Разрешить', deny: 'Отклонить'
    },
    dashboard: {
      title: 'Обзор', ready: 'готов', notReady: 'не готов', unknown: 'неизвестно', users: 'Пользователи', roles: 'Роли',
      clients: 'OAuth-клиенты', providers: 'LDAP-провайдеры'
    },
    users: {
      title: 'Пользователи', create: 'Новый пользователь', passwordHint: 'пароль (не менее 12 символов)', lastLogin: 'Последний вход',
      roles: 'Роли', groups: 'Группы', noGroups: 'Группы ещё не созданы.', confirmDelete: 'Удалить пользователя «{name}»? Учётная запись будет деактивирована.'
    },
    roles: { title: 'Роли', create: 'Новая роль', permissions: 'Разрешения', confirmDelete: 'Удалить роль «{code}»?' },
    groups: {
      title: 'Группы', create: 'Новая группа', roles: 'Роли', empty: 'Групп пока нет.',
      help: 'Участники наследуют все роли своих групп. Сопоставление LDAP-групп настраивается на странице LDAP.',
      confirmDelete: 'Удалить группу «{code}»?'
    },
    clients: {
      title: 'OAuth-клиенты', create: 'Новый клиент', secretOnce: 'Секрет для {client} (показывается только один раз):',
      scopes: 'Разрешённые scope (через пробел)', redirectUris: 'Redirect URI (через пробел или запятую)',
      postLogoutUris: 'Post-logout redirect URI', backchannelUri: 'Back-channel logout URI', skipConsent: 'Не запрашивать согласие',
      consent: 'Согласие', required: 'требуется', skipped: 'не требуется', confirmDelete: 'Удалить клиента «{client}»?'
    },
    ldap: {
      title: 'LDAP-провайдеры', create: 'Новый провайдер', host: 'Хост', port: 'Порт', bindPassword: 'Пароль bind',
      userFilter: 'Фильтр пользователей', usernameAttr: 'Атрибут имени пользователя', emailAttr: 'Атрибут email',
      displayNameAttr: 'Атрибут отображаемого имени', groupAttr: 'Атрибут группы', test: 'Проверить подключение',
      connectionOK: 'Подключение успешно.', connectionFailed: 'Ошибка подключения: {error}', security: 'Защита', plain: 'без TLS',
      mappings: 'Сопоставления групп', mappingHelp: 'Группы каталога из атрибута {attribute} сопоставляются с группами SSO при входе.',
      selectGroup: 'Группа SSO…', addMapping: 'Добавить сопоставление', confirmDelete: 'Удалить LDAP-провайдера «{name}»?'
    },
    idp: {
      title: 'Поставщики удостоверений', create: 'Новый провайдер', help: 'Внешний вход («Продолжить через …»). Для Google и GitHub URL endpoint заполняются автоматически. Зарегистрируйте у провайдера callback:',
      clientSecret: 'Секрет клиента', scopes: 'Scope', authorizeURL: 'URL авторизации', tokenURL: 'URL токена', userinfoURL: 'URL UserInfo',
      empty: 'Поставщики удостоверений не настроены.', confirmDelete: 'Удалить провайдера «{code}»? Связанные пользователи потеряют этот способ входа.'
    },
    audit: {
      title: 'Журнал аудита', actionHint: 'действие (например, login_failed)', time: 'Время', action: 'Действие', target: 'Объект', actor: 'Инициатор', empty: 'Событий нет.'
    },
    account: {
      title: 'Моя учётная запись', profile: 'Профиль', verified: 'подтверждён', notVerified: 'не подтверждён', sendVerification: 'Отправить письмо для подтверждения',
      verificationSent: 'Письмо для подтверждения отправлено.', mfa: 'Двухфакторная аутентификация', on: 'включена', off: 'выключена',
      recoveryCodes: 'Коды восстановления', recoveryHelp: 'Сохраните их в безопасном месте: повторно они не показываются.', setupMFA: 'Настроить приложение-аутентификатор',
      scanQR: 'Отсканируйте QR-код в приложении-аутентификаторе, затем введите текущий код.', secret: 'Секрет', activate: 'Активировать',
      codeHint: 'TOTP или код восстановления', disableMFA: 'Отключить MFA', mfaAlready: 'MFA уже включена.', mfaDisabled: 'MFA отключена.',
      changePassword: 'Сменить пароль', currentPassword: 'текущий пароль', newPasswordHint: 'новый пароль (не менее 12 символов)', repeatPassword: 'повторите новый пароль',
      passwordChanged: 'Пароль изменён.', sessions: 'Активные сеансы', signOutEverywhere: 'Выйти на всех устройствах', revoke: 'Отозвать',
      confirmSignOut: 'Выйти на всех устройствах? Потребуется повторный вход.'
    }
  }
}

export default createI18n({ legacy: false, locale: 'ru', fallbackLocale: 'ru', messages })
