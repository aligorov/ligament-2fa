-- 0007_group_settings: приоритет групп, настройки 2FA-каналов, RADIUS Push, RADIUS Reply и VLAN.

ALTER TABLE groups ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 50;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS prefer_channels JSONB;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS radius_push BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS radius_reply JSONB;
