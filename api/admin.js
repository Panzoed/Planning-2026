const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action, userId, approved, newPassword } = req.body || {};

  if (action === 'list_users') {
    const { data } = await supabase.from('users').select('id, email, nom, prenom, approved, created_at').order('created_at', { ascending:false });
    return res.json(data || []);
  }

  if (action === 'approve') {
    await supabase.from('users').update({ approved }).eq('id', userId);
    return res.json({ ok:true });
  }

  if (action === 'delete') {
    await supabase.from('users').delete().eq('id', userId);
    return res.json({ ok:true });
  }

  if (action === 'reset_password') {
    const hash = await bcrypt.hash(newPassword, 10);
    await supabase.from('users').update({ password_hash:hash }).eq('id', userId);
    return res.json({ ok:true });
  }

  return res.status(400).json({ error:'Action inconnue' });
};