-- ----------------------------------- TABLES ------------------------------------
CREATE TABLE `tactic` (
  `id` varchar(7) NOT NULL,
  `name` varchar(25) NOT NULL,
  `link` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `technique` (
  `id` varchar(7) NOT NULL,
  `name` varchar(60) NOT NULL,
  `link` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`id`)
  UNIQUE KEY `name_UNIQUE` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `relation_tactic_technique` (
  `ta_id` varchar(7) NOT NULL,
  `t_id` varchar(7) NOT NULL,
  PRIMARY KEY (`ta_id`,`t_id`),
  KEY `technique_idx` (`t_id`),
  CONSTRAINT `tactic` FOREIGN KEY (`ta_id`) REFERENCES `tactic` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `technique` FOREIGN KEY (`t_id`) REFERENCES `technique` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `sub_technique` (
  `id` varchar(7) NOT NULL,
  `sub_id` varchar(5) NOT NULL,
  `name` varchar(60) NOT NULL,
  `link` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`id`,`sub_id`),
  KEY `sub_id_idx` (`sub_id`),
  CONSTRAINT `t_id` FOREIGN KEY (`id`) REFERENCES `technique` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `custom_rule` (
  `alert_id` varchar(200) NOT NULL,
  `ta_id` varchar(7) NOT NULL,
  `t_id` varchar(7) NOT NULL,
  `subt_id` varchar(5) NOT NULL,
  PRIMARY KEY (`alert_id`,`ta_id`,`t_id`,`subt_id`),
  KEY `ta_id_idx` (`ta_id`),
  KEY `t_id_idx` (`t_id`),
  KEY `subt_id_idx` (`subt_id`),
  KEY `cr_alert_id_idx` (`alert_id`),
  CONSTRAINT `cr_alert_id` FOREIGN KEY (`alert_id`) REFERENCES `custom_alert` (`id`),
  CONSTRAINT `cr_t_id` FOREIGN KEY (`t_id`) REFERENCES `technique` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `cr_ta_id` FOREIGN KEY (`ta_id`) REFERENCES `tactic` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `custom_alert` (
  `id` varchar(200) NOT NULL,
  `type` varchar(10) DEFAULT NULL,
  `tool` tinyint DEFAULT '-1',
  `miss_num` int unsigned NOT NULL DEFAULT '1',
  `description` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci

CREATE TABLE `tool` (
  `id` tinyint NOT NULL,
  `name` varchar(20) NOT NULL,
  `type` varchar(45) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci


-- ----------------------------------- TRIGGERS ------------------------------------
-- If an alert is matched to a Mitre category, set to 0 miss_num on custom_alert table
CREATE DEFINER=`root`@`%` TRIGGER `custom_alertTRIGGER` AFTER INSERT ON `custom_rule` FOR EACH ROW BEGIN
	UPDATE `mitrettp`.`custom_alert` SET miss_num = 0 WHERE id LIKE NEW.alert_id;
END

-- If a matched alert (rule) is deleted, set to 1 miss_num on custom_alert table
CREATE DEFINER=`root`@`%` TRIGGER `custom_rule_AFTER_DELETE` AFTER DELETE ON `custom_rule` FOR EACH ROW BEGIN
	DECLARE num INT;
	SET num = (SELECT COUNT(*) FROM `mitrettp`.`custom_rule` WHERE alert_id LIKE OLD.alert_id);
    IF num < 1 THEN
		UPDATE `mitrettp`.`custom_alert` SET miss_num = 1 WHERE id LIKE OLD.alert_id;
	END IF;
END

-- Check to avoid insertion of a rule with unmatched tactic and technique
CREATE DEFINER=`root`@`%` TRIGGER `custom_rule_BEFORE_INSERT` BEFORE INSERT ON `custom_rule` FOR EACH ROW BEGIN
	DECLARE num_t INT;
    DECLARE num_subt INT;

	SELECT COUNT(*) INTO num_t FROM `mitrettp`.`relation_tactic_technique` WHERE ta_id LIKE NEW.ta_id AND t_id LIKE NEW.t_id;
    IF num_t < 1 THEN
		SIGNAL SQLSTATE '04666' SET MESSAGE_TEXT = 'Invalid relation between tactic and technique in mitrettp.relation_tactic_technique';
	END IF;


    IF NEW.subt_id NOT LIKE 'void' AND NEW.subt_id NOT LIKE 'Other' THEN
		SELECT COUNT(*) INTO num_subt FROM `mitrettp`.`sub_technique` WHERE id LIKE NEW.t_id AND sub_id LIKE NEW.subt_id;
		IF num_subt < 1 THEN
			SIGNAL SQLSTATE '04666' SET MESSAGE_TEXT = 'Sub technique not existing in mitrettp.sub_technique';
		END IF;
    END IF;
END



-- Entry per gestire i casi particolari nella tabella custom_rule
-- I casi particolari sono:
-- 1) Selezione di una tecnica che non ha delle sotto-tecniche e quindi il campo subt_id deve essere void, quindi deve essere presente un'entry fittizia nella tabella delle sotto-tecniche e a cascata anche nelle tabelle delle tecniche e tattiche.
-- 2) Selezione di una tecnica che ha delle sotto-tecniche ma senza selezionare alcuna di esse (Other) viene considerata come selezione di una sotto-tecnica non ancora censita

INSERT INTO `mitrettp`.`tactic` (`id`, `sub_id`, `name`, `link`) VALUES ('void', 'void', 'void', 'Sotto-tecnica fittizia per la gestione di custom_rule');
INSERT INTO `mitrettp`.`technique` (`id`, `sub_id`, `name`, `link`) VALUES ('void', 'void', 'void', 'Sotto-tecnica fittizia per la gestione di custom_rule');
INSERT INTO `mitrettp`.`sub_technique` (`id`, `sub_id`, `name`, `link`) VALUES ('void', 'void', 'void', 'Sotto-tecnica fittizia per la gestione di custom_rule');
INSERT INTO `mitrettp`.`sub_technique` (`id`, `sub_id`, `name`, `link`) VALUES ('void', 'Other', 'Other', 'Sotto-tecnica fittizia per la gestione di custom_rule');
