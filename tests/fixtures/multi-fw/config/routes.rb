Rails.application.routes.draw do
  get '/status', to: 'status#show'
  resources :invoices
end
