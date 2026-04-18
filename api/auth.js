const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const ADMIN_EMAIL = 'siciliano_messinese@hotmail.it';
const SITE_URL = process.env.SITE_URL || 'https://planning-2026.vercel.app';

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action, email, password, nom, prenom, token, newPassword } = req.body || {};

  if (action === 'login') {
    if (email === ADMIN_EMAIL) {
      const ok = await bcrypt.compare(password, process.env.ADMIN_HASH);
      if (ok) return res.json({ role:'admin', nom:'Admin', prenom:'' });
      return res.status(401).json({ error:'Mot de passe incorrect' });
    }
    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(404).json({ error:'Email non trouvé' });
    if (!user.approved) return res.status(403).json({ error:"Compte en attente d'approbation" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error:'Mot de passe incorrect' });
    return res.json({ role:'user', nom:user.nom, prenom:user.prenom });
  }

  if (action === 'register') {
    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(409).json({ error:'Email déjà utilisé' });
    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from('users').insert({ email, nom, prenom, password_hash:hash });
    if (error) return res.status(500).json({ error:'Erreur inscription' });
    return res.json({ message:"Demande envoyée, en attente d'approbation" });
  }

  if (action === 'forgot') {
    const { data: user } = await supabase.from('users').select('id, nom, prenom').eq('email', email).single();
    if (!user) return res.status(404).json({ error:'Email non trouvé' });
    const t = Math.random().toString(36).substring(2) + Date.now().toString(36);
    const expires = new Date(Date.now() + 3600000).toISOString();
    await supabase.from('users').update({ reset_token:t, reset_expires:expires }).eq('id', user.id);
    const resetLink = SITE_URL + '?reset=' + t;
    await fetch('https://api.brevo.com/v3/smtp/email', {
      method:'POST',
      headers:{ 'api-key':process.env.BREVO_KEY, 'Content-Type':'application/json' },
      body:JSON.stringify({
        sender:{ name:'Planning 2026', email:ADMIN_EMAIL },
        to:[{ email, name:user.prenom+' '+user.nom }],
        subject:'🔐 Réinitialisation de votre mot de passe',
        htmlContent:'<div style="font-family:sans-serif;padding:20px"><h2 style="color:#3B82F6">Planning 2026</h2><p>Bonjour '+user.prenom+',</p><p>Cliquez ci-dessous pour réinitialiser votre mot de passe :</p><a href="'+resetLink+'" style="display:inline-block;background:#3B82F6;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">Réinitialiser mon mot de passe</a><p style="color:#666;font-size:12px">Lien valable 1 heure.</p></div>'
      })
    });
    return res.json({ message:'Email envoyé !' });
  }

  if (action === 'reset') {
    const { data: user } = await supabase.from('users').select('id, reset_expires').eq('reset_token', token).single();
    if (!user) return res.status(404).json({ error:'Lien invalide' });
    if (new Date(user.reset_expires) < new Date()) return res.status(400).json({ error:'Lien expiré' });
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash:hash, reset_token:null, reset_expires:null }).eq('id', user.id);
    return res.json({ message:'Mot de passe mis à jour !' });
  }

  return res.status(400).json({ error:'Action inconnue' });
};